// SPDX-License-Identifier: Apache-2.0
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace RdpWrapMaintenance {
    public sealed class MaintenanceException : Exception {
        public int ExitCode { get; private set; }
        public MaintenanceException(string message, int code = 2) : base(message) { ExitCode = code; }
    }
    public static class Files {
        public static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        public static string Hash(byte[] bytes) { using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", ""); }
        public static string HashFile(string path) { return File.Exists(path) ? Hash(File.ReadAllBytes(path)) : null; }
        public static string Text(string path) { return Utf8.GetString(File.ReadAllBytes(path)); }
        public static void AtomicWrite(string path, byte[] bytes) {
            string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try {
                File.WriteAllBytes(temp, bytes);
                // The original is already saved and hashed before stopping SCM.
                // Keep the atomic rename on the target volume even if logs are
                // on another drive.
                if (File.Exists(path)) File.Replace(temp, path, null);
                else File.Move(temp, path);
            } finally { if (File.Exists(temp)) File.Delete(temp); }
        }
    }
    public sealed class ImageSection {
        public ulong Start, Length; public bool Executable;
    }
    public sealed class PeImage {
        public string Architecture; public ulong ImageSize; public readonly List<ImageSection> Sections = new List<ImageSection>();
        public static PeImage Read(byte[] bytes) {
            if (bytes.Length < 256 || bytes[0] != 'M' || bytes[1] != 'Z') throw new MaintenanceException("Invalid PE image");
            int pe = BitConverter.ToInt32(bytes, 0x3c);
            if (pe < 0 || (long)pe + 24 >= bytes.Length || BitConverter.ToUInt32(bytes, pe) != 0x4550) throw new MaintenanceException("Invalid PE header");
            ushort machine = BitConverter.ToUInt16(bytes, pe + 4);
            if (machine != 0x8664 && machine != 0x14c) throw new MaintenanceException("Only x64 and x86 are supported");
            int count = BitConverter.ToUInt16(bytes, pe + 6), optional = BitConverter.ToUInt16(bytes, pe + 20), start = pe + 24 + optional;
            if (count == 0 || count > 96 || optional < 60 || (long)start + 40 * count > bytes.Length) throw new MaintenanceException("Invalid PE sections");
            var image = new PeImage { Architecture = machine == 0x8664 ? "x64" : "x86", ImageSize = BitConverter.ToUInt32(bytes, pe + 24 + 56) };
            for (int i = 0; i < count; i++) {
                int p = start + 40 * i;
                image.Sections.Add(new ImageSection { Start = BitConverter.ToUInt32(bytes, p + 12), Length = Math.Max(BitConverter.ToUInt32(bytes, p + 8), BitConverter.ToUInt32(bytes, p + 16)), Executable = (BitConverter.ToUInt32(bytes, p + 36) & 0x20000000) != 0 });
            }
            return image;
        }
        public void AssertRva(string hex, int length, bool executable) {
            if (!Regex.IsMatch(hex ?? "", "^[0-9A-Fa-f]{1,8}$")) throw new MaintenanceException("Invalid RVA: " + hex);
            ulong rva = Convert.ToUInt64(hex, 16);
            var section = Sections.Where(s => rva >= s.Start && rva + (ulong)length <= s.Start + s.Length).ToArray();
            if (length < 1 || section.Length != 1 || rva + (ulong)length > ImageSize || (executable && !section[0].Executable)) throw new MaintenanceException("RVA outside the expected PE section: " + hex);
        }
    }
    public sealed class Ini {
        public readonly Dictionary<string, Dictionary<string, string>> Sections = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        public static Ini Parse(string text) {
            var ini = new Ini(); Dictionary<string, string> section = null;
            foreach (string line in Regex.Split(text, "\\r?\\n")) {
                string s = line.Trim().TrimStart('\ufeff');
                if (s.Length == 0 || s.StartsWith(";") || s.StartsWith("#")) continue;
                var m = Regex.Match(s, "^\\[([^\\]]+)\\]$");
                if (m.Success) {
                    string name = m.Groups[1].Value;
                    if (ini.Sections.ContainsKey(name)) throw new MaintenanceException("Duplicate INI section: " + name);
                    section = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); ini.Sections.Add(name, section);
                } else {
                    int split = s.IndexOf('=');
                    if (section == null || split < 1) throw new MaintenanceException("Malformed INI line: " + s);
                    string key = s.Substring(0, split).Trim();
                    if (section.ContainsKey(key)) throw new MaintenanceException("Duplicate INI key: " + key);
                    section.Add(key, s.Substring(split + 1).Trim());
                }
            }
            return ini;
        }
        public void Validate(string version, PeImage image) {
            if (!Sections.ContainsKey(version)) throw new MaintenanceException("Missing exact version: [" + version + "]");
            if (!Sections.ContainsKey("PatchCodes")) throw new MaintenanceException("Missing PatchCodes");
            var s = Sections[version]; string arch = image.Architecture;
            foreach (string kind in new[] { "LocalOnly", "SingleUser", "DefPolicy" }) {
                if (!Enabled(s, kind + "Patch." + arch)) continue;
                string code = Value(s, kind + "Code." + arch), hex = Value(Sections["PatchCodes"], code);
                ValidateHex(hex); image.AssertRva(Value(s, kind + "Offset." + arch), hex.Length / 2, true);
            }
            if (!Enabled(s, "SingleUserPatch." + arch) || !Enabled(s, "DefPolicyPatch." + arch)) throw new MaintenanceException("Concurrent-session patches are not enabled");
            foreach (string kind in new[] { "SLInit", "SLPolicy" }) {
                if (!Enabled(s, kind + "Hook." + arch)) continue;
                string function = Value(s, kind + "Func." + arch);
                if (function != "New_CSLQuery_Initialize" && function != "New_SLQuery_Wrapper") throw new MaintenanceException("Unsupported wrapper hook: " + function);
                image.AssertRva(Value(s, kind + "Offset." + arch), 1, true);
            }
            if (Enabled(s, "SLInitHook." + arch)) {
                if (!Sections.ContainsKey(version + "-SLInit")) throw new MaintenanceException("Missing SLInit section");
                foreach (string key in new[] { "bInitialized", "bServerSku", "lMaxUserSessions", "bAppServerAllowed", "bRemoteConnAllowed", "bMultimonAllowed", "ulMaxDebugSessions", "bFUSEnabled" }) image.AssertRva(Value(Sections[version + "-SLInit"], key + "." + arch), 4, false);
            }
        }
        public static bool Enabled(Dictionary<string, string> s, string key) {
            string v; if (!s.TryGetValue(key, out v)) return false;
            if (v != "0" && v != "1") throw new MaintenanceException("Invalid flag: " + key); return v == "1";
        }
        public static string Value(Dictionary<string, string> s, string key) {
            string v; if (!s.TryGetValue(key, out v)) throw new MaintenanceException("Missing INI key: " + key); return v;
        }
        public static void ValidateHex(string hex) { if (hex.Length > 512 || !Regex.IsMatch(hex, "^(?:[0-9A-Fa-f]{2})+$")) throw new MaintenanceException("Invalid patch bytes"); }
        public static string Pattern(string name) { return "(?ms)^\\[" + Regex.Escape(name) + "\\][ \\t]*\\r?\\n.*?(?=^\\[|\\z)"; }
        public static string SectionText(string text, string name) {
            var m = Regex.Matches(text, Pattern(name)); if (m.Count != 1) throw new MaintenanceException("Cannot locate exact INI section: " + name); return m[0].Value.TrimEnd();
        }
        static bool Equal(Dictionary<string, string> a, Dictionary<string, string> b) { return a.Count == b.Count && a.All(p => b.ContainsKey(p.Key) && p.Value.Equals(b[p.Key], StringComparison.OrdinalIgnoreCase)); }
        public static string Merge(string original, string source, string version, PeImage image, List<string> changes) {
            var old = Parse(original); var incoming = Parse(source); incoming.Validate(version, image);
            if (!old.Sections.ContainsKey("PatchCodes")) throw new MaintenanceException("Installed INI lacks PatchCodes; configuration was not replaced");
            string nl = original.Contains("\n") && !original.Contains("\r\n") ? "\n" : "\r\n", candidate = original;
            var definitions = new List<string>();
            foreach (string code in incoming.Sections[version].Where(p => Regex.IsMatch(p.Key, "Code\\.x(?:64|86)$")).Select(p => p.Value).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(s => s, StringComparer.OrdinalIgnoreCase)) {
                string hex = Value(incoming.Sections["PatchCodes"], code); ValidateHex(hex);
                string existing;
                if (old.Sections["PatchCodes"].TryGetValue(code, out existing)) {
                    if (!existing.Equals(hex, StringComparison.OrdinalIgnoreCase)) throw new MaintenanceException("Conflicting shared PatchCodes: " + code);
                } else { definitions.Add(code + "=" + hex); changes.Add("Added PatchCodes/" + code); }
            }
            if (definitions.Count != 0) {
                var marker = Regex.Match(candidate, "(?m)^\\[PatchCodes\\][ \\t]*\\r?\\n");
                if (!marker.Success) throw new MaintenanceException("Cannot locate PatchCodes header");
                candidate = candidate.Insert(marker.Index + marker.Length, string.Join(nl, definitions) + nl);
            }
            var names = new List<string> { version }; if (incoming.Sections.ContainsKey(version + "-SLInit")) names.Add(version + "-SLInit");
            foreach (string name in names) {
                string replacement = Regex.Replace(SectionText(source, name), "\\r?\\n", nl);
                if (old.Sections.ContainsKey(name)) {
                    if (Equal(old.Sections[name], incoming.Sections[name])) continue;
                    var m = Regex.Match(candidate, Pattern(name));
                    if (!m.Success) throw new MaintenanceException("Cannot replace exact section: " + name);
                    candidate = candidate.Remove(m.Index, m.Length).Insert(m.Index, replacement + nl + nl); changes.Add("Updated [" + name + "]");
                } else { candidate += nl + nl + replacement + nl; changes.Add("Added [" + name + "]"); }
            }
            var result = Parse(candidate); result.Validate(version, image);
            foreach (var s in old.Sections) {
                if (names.Contains(s.Key)) continue;
                foreach (var pair in s.Value) if (!result.Sections.ContainsKey(s.Key) || Value(result.Sections[s.Key], pair.Key) != pair.Value) throw new MaintenanceException("Unrelated INI data changed: " + s.Key + "/" + pair.Key);
                if (s.Key != "PatchCodes" && s.Value.Count != result.Sections[s.Key].Count) throw new MaintenanceException("Unrelated section changed");
            }
            return candidate;
        }
    }
    public sealed class Session {
        public int Id, Protocol; public string User, Station, State;
        public bool Blocks { get { return Protocol == 2 || (Station ?? "").StartsWith("rdp-", StringComparison.OrdinalIgnoreCase) || (new[] { "Active", "Disconnected", "Connected", "ConnectQuery", "Shadow", "LogonPresent" }.Contains(State) && !string.Equals(Station, "console", StringComparison.OrdinalIgnoreCase)); } }
    }
    public static class SessionGuard {
        public static List<Session> Read(Func<List<Session>> wts, Func<bool> stopped, Func<List<Session>> lsa) {
            try { return wts(); }
            catch {
                // A dead TermService can make WTS unavailable. Only a confirmed
                // stopped service can use the independent LSA logon table; both
                // remote and ambiguous non-console logons still block changes.
                // A running/unverifiable service never converts a WTS failure
                // into an assumption that no sessions exist.
                if (!stopped()) throw;
                return lsa();
            }
        }
    }
    public sealed class Snapshot {
        public string Version, Architecture, TermsrvPath, TermsrvHash, ServiceDll, WrapperPath, IniPath, WrapperHash, IniHash, Runtime;
        public int ProcessId; public DateTime? ProcessStarted;
        public bool IsAdmin, Registered, SignedTermsrv, ServiceRunning, Listener, RdpEnabled;
        public string SessionError, RuntimeError; public List<Session> Sessions = new List<Session>();
        public PeImage Image;
        public bool Concurrent { get { return Sessions.Any(s => s.State == "Active" && string.Equals(s.Station, "console", StringComparison.OrdinalIgnoreCase)) && Sessions.Any(s => s.State == "Active" && s.Protocol == 2); } }
    }
    public interface IPlatform {
        Snapshot Read(); void GuardSessions(); void Register(string path); void StopService(); void StartService();
    }
    public sealed class Payload {
        public byte[] Wrapper; public string DefaultIni;
    }
    public sealed class Options {
        public bool CheckOnly; public string SourceFile; public string LogDirectory;
    }
    public sealed class Engine {
        readonly IPlatform platform; readonly Payload payload; readonly Options options;
        readonly Func<string, string> download;
        public readonly Dictionary<string, object> Report = new Dictionary<string, object>();
        public Engine(IPlatform platform, Payload payload, Options options, Func<string, string> download) { this.platform = platform; this.payload = payload; this.options = options; this.download = download; }
        static bool Supported(string text, Snapshot s) { try { Ini.Parse(text).Validate(s.Version, s.Image); return true; } catch { return false; } }
        string PendingPath { get { return Path.Combine(options.LogDirectory, "pending-reload.json"); } }
        bool Pending(Snapshot s) {
            if (!File.Exists(PendingPath)) return false;
            var data = Program.Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(PendingPath));
            if (Convert.ToString(data["Version"]) != s.Version || Convert.ToString(data["IniHash"]) != s.IniHash || Convert.ToString(data["WrapperHash"]) != s.WrapperHash) return false;
            DateTime applied = DateTime.Parse(Convert.ToString(data["AppliedUtc"]), null, System.Globalization.DateTimeStyles.RoundtripKind);
            return !s.ProcessStarted.HasValue || s.ProcessStarted.Value.ToUniversalTime() <= applied;
        }
        void Fresh(Snapshot original) {
            platform.GuardSessions(); var current = platform.Read();
            if (current.TermsrvHash != original.TermsrvHash || current.ServiceDll != original.ServiceDll || current.IniHash != original.IniHash || current.WrapperHash != original.WrapperHash) throw new MaintenanceException("Host changed during preparation; retry after Windows Update completes");
        }
        void StableDuringApply(Snapshot original, string expectedDll, string expectedIni) {
            platform.GuardSessions(); var current = platform.Read();
            if (current.TermsrvHash != original.TermsrvHash || current.ServiceDll != original.ServiceDll || current.WrapperHash != expectedDll || current.IniHash != expectedIni) throw new MaintenanceException("Files or registration changed immediately before a write");
        }
        string Candidate(string original, Snapshot s, List<string> changes) {
            // A broken document cannot be merged while preserving its unrelated
            // settings. Detect that before contacting any update source.
            Ini.Parse(original);
            if (Supported(original, s)) return original;
            var attempts = new List<Dictionary<string, string>>(); Report["SourceAttempts"] = attempts;
            if (options.SourceFile != null) {
                string text = Files.Text(options.SourceFile); string merged = Ini.Merge(original, text, s.Version, s.Image, changes);
                Report["Source"] = Path.GetFullPath(options.SourceFile); Report["SourceSha256"] = Files.HashFile(options.SourceFile); return merged;
            }
            try {
                var tentative = new List<string>();
                string merged = Ini.Merge(original, payload.DefaultIni, s.Version, s.Image, tentative); changes.AddRange(tentative);
                Report["Source"] = "Embedded fork INI"; Report["SourceSha256"] = Files.Hash(Files.Utf8.GetBytes(payload.DefaultIni)); return merged;
            } catch (MaintenanceException e) { attempts.Add(new Dictionary<string, string> { { "Source", "Embedded fork INI" }, { "Result", e.Message } }); }
            foreach (string url in new[] { "https://raw.githubusercontent.com/tomek-sztuk/rdpwrap/master/res/rdpwrap.ini", "https://raw.githubusercontent.com/sebaxakerhtc/rdpwrap.ini/master/rdpwrap.ini", "https://raw.githubusercontent.com/asmtron/rdpwrap/master/res/rdpwrap.ini", "https://raw.githubusercontent.com/stascorp/rdpwrap/master/res/rdpwrap.ini" }) {
                try {
                    Report["NetworkUsed"] = true; string text = download(url); var tentative = new List<string>();
                    string merged = Ini.Merge(original, text, s.Version, s.Image, tentative); changes.AddRange(tentative);
                    Report["Source"] = url; Report["SourceSha256"] = Files.Hash(Files.Utf8.GetBytes(text)); return merged;
                } catch (Exception e) { attempts.Add(new Dictionary<string, string> { { "Source", url }, { "Result", e.Message } }); }
            }
            throw new MaintenanceException("No validated entry for exact termsrv " + s.Version + "; no offsets guessed and no installation performed");
        }
        public int Run() {
            Report["StartedUtc"] = DateTime.UtcNow.ToString("o"); Report["NetworkUsed"] = false; Report["Applied"] = false; Report["ServiceReloaded"] = false;
            string backup = null; Snapshot before = null; bool changed = false; string oursIni = null, oursDll = null, oursRegistration = null;
            try {
                before = platform.Read(); Report["Before"] = before;
                string original = File.Exists(before.IniPath) ? Files.Text(before.IniPath) : payload.DefaultIni;
                bool iniGood = File.Exists(before.IniPath) && Supported(original, before), dllGood = before.WrapperHash == Files.Hash(payload.Wrapper);
                bool pending = Pending(before);
                bool runtimeGood = before.Runtime == "Loaded" || (before.Runtime == "Unknown" && before.Concurrent);
                bool healthy = before.Registered && dllGood && iniGood && before.SignedTermsrv && before.ServiceRunning && before.Listener && before.RdpEnabled && before.SessionError == null && runtimeGood && !pending;
                Report["ExactVersionSupported"] = iniGood; Report["LibraryMatchesBundle"] = dllGood; Report["PendingServiceReload"] = pending;
                if (options.CheckOnly || healthy) { Report["State"] = healthy ? "Healthy" : "NeedsAttention"; return healthy ? 0 : 1; }
                if (!before.IsAdmin && before.SessionError != null) throw new MaintenanceException("Administrator privileges required to inspect sessions of the stopped/unreadable service", 4);
                platform.GuardSessions();
                if (!before.IsAdmin) throw new MaintenanceException("Administrator privileges required; unattended mode never opens UAC", 4);
                if (!before.SignedTermsrv) throw new MaintenanceException("termsrv.dll signature is invalid; system DLLs are not replaced");
                if (!before.RdpEnabled) throw new MaintenanceException("Windows Remote Desktop is disabled; access settings are left to the administrator");
                if (before.Registered && dllGood && iniGood && before.ServiceRunning && before.Listener && before.Runtime == "Unknown" && !pending) throw new MaintenanceException("Runtime modules could not be inspected; no speculative service reload", 1);
                if (PeImage.Read(payload.Wrapper).Architecture != before.Architecture) throw new MaintenanceException("Embedded wrapper architecture mismatch");
                var changes = new List<string>(); string candidate = Candidate(original, before, changes); Report["Changes"] = changes;
                Fresh(before);
                if (!dllGood || !iniGood || !before.Registered) {
                    backup = Path.Combine(options.LogDirectory, "backups", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8)); Directory.CreateDirectory(backup);
                    if (File.Exists(before.WrapperPath)) File.Copy(before.WrapperPath, Path.Combine(backup, "rdpwrap.dll"));
                    if (File.Exists(before.IniPath)) File.Copy(before.IniPath, Path.Combine(backup, "rdpwrap.ini"));
                    File.WriteAllText(Path.Combine(backup, "before.json"), Program.Json.Serialize(before), Files.Utf8); Report["Backup"] = backup;
                    Directory.CreateDirectory(Path.GetDirectoryName(before.WrapperPath));
                    // Stop through SCM, never terminate a shared svchost process.
                    // Guard immediately before stopping and before every actual write.
                    platform.GuardSessions(); changed = true; platform.StopService();
                    // Stopping the service is itself a state change, so failures below
                    // must also restore its previous running state.
                    StableDuringApply(before, before.WrapperHash, before.IniHash);
                    if (!dllGood) { Files.AtomicWrite(before.WrapperPath, payload.Wrapper); oursDll = Files.Hash(payload.Wrapper); Report["RecoveredLibrary"] = true; }
                    StableDuringApply(before, oursDll ?? before.WrapperHash, before.IniHash);
                    if (!iniGood) { Files.AtomicWrite(before.IniPath, Files.Utf8.GetBytes(candidate)); oursIni = Files.Hash(Files.Utf8.GetBytes(candidate)); }
                    if (!before.Registered) { StableDuringApply(before, oursDll ?? before.WrapperHash, oursIni ?? before.IniHash); platform.Register(before.WrapperPath); oursRegistration = before.WrapperPath; Report["RegisteredLibrary"] = true; }
                    Report["Applied"] = true;
                    var marker = new Dictionary<string, object> { { "Version", before.Version }, { "IniHash", Files.HashFile(before.IniPath) }, { "WrapperHash", Files.HashFile(before.WrapperPath) }, { "AppliedUtc", DateTime.UtcNow.ToString("o") } };
                    File.WriteAllText(PendingPath, Program.Json.Serialize(marker), Files.Utf8);
                }
                platform.GuardSessions();
                if (Files.HashFile(before.TermsrvPath) != before.TermsrvHash) throw new MaintenanceException("termsrv.dll changed before service start");
                if (!changed) { changed = true; platform.StopService(); }
                platform.GuardSessions(); platform.StartService(); Report["ServiceReloaded"] = true;
                var after = platform.Read(); Report["After"] = after;
                if (!after.Registered || after.WrapperHash != Files.Hash(payload.Wrapper) || !after.ServiceRunning || !after.Listener || after.Runtime != "Loaded" || after.SessionError != null || !Supported(Files.Text(after.IniPath), after) || after.TermsrvHash != before.TermsrvHash) throw new MaintenanceException("Post-repair verification failed; inspect report before retrying");
                if (File.Exists(PendingPath)) File.Delete(PendingPath);
                Report["State"] = "Healthy"; return 0;
            } catch (Exception e) {
                var maintenance = e as MaintenanceException; int code = maintenance == null ? 2 : maintenance.ExitCode;
                Report["Error"] = e.Message; Report["State"] = code == 3 ? "Held" : code == 4 ? "AdministratorRequired" : "Failed";
                if (code != 3 && changed && before != null) {
                    try {
                        // Reload-only failures also restore the original service
                        // state, without creating a file backup or rewriting INI.
                        if (backup == null) {
                            platform.GuardSessions();
                            if (before.ServiceRunning) platform.StartService();
                            else platform.StopService();
                            Report["ServiceStateRestored"] = true;
                            return code;
                        }
                        platform.GuardSessions(); var current = platform.Read();
                        if ((oursIni != null && current.IniHash != oursIni) || (oursDll != null && current.WrapperHash != oursDll) || (oursRegistration != null && current.ServiceDll != oursRegistration)) throw new MaintenanceException("Later external changes prevent rollback");
                        platform.StopService(); platform.GuardSessions();
                        Restore(before.IniPath, Path.Combine(backup, "rdpwrap.ini"), before.IniHash, oursIni);
                        platform.GuardSessions(); Restore(before.WrapperPath, Path.Combine(backup, "rdpwrap.dll"), before.WrapperHash, oursDll);
                        if (oursRegistration != null) { platform.GuardSessions(); platform.Register(before.ServiceDll); }
                        if (before.ServiceRunning) { platform.GuardSessions(); platform.StartService(); }
                        if (File.Exists(PendingPath)) File.Delete(PendingPath);
                        Report["RolledBack"] = true; Report["Applied"] = false;
                    } catch (Exception rollback) { Report["RollbackError"] = rollback.Message; }
                }
                return code;
            } finally { Report["CompletedUtc"] = DateTime.UtcNow.ToString("o"); }
        }
        static void Restore(string target, string backup, string beforeHash, string oursHash) {
            if (oursHash == null) return;
            if (beforeHash == null) { if (File.Exists(target)) File.Delete(target); }
            else { if (!File.Exists(backup) || Files.HashFile(backup) != beforeHash) throw new MaintenanceException("Backup hash mismatch"); Files.AtomicWrite(target, File.ReadAllBytes(backup)); }
        }
    }
}
