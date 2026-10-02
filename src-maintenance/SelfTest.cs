// SPDX-License-Identifier: Apache-2.0
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace RdpWrapMaintenance {
    public static class SelfTest {
        static int passed, failed;
        static readonly List<string> roots = new List<string>();
        static void Assert(bool value, string why) { if (!value) throw new Exception(why); }
        static void Test(string name, Action body) { try { body(); Console.WriteLine("PASS " + name); passed++; } catch (Exception e) { Console.WriteLine("FAIL " + name + ": " + e.Message); failed++; } }
        static void Reject(Action body) { bool threw = false; try { body(); } catch (MaintenanceException) { threw = true; } Assert(threw, "Input was accepted"); }
        public static int Run() {
            var payload = Resources.Payload("x64"); string current = payload.DefaultIni, version = "10.0.26100.9444";
            var image = new PeImage { Architecture = "x64", ImageSize = 0x500000 }; image.Sections.Add(new ImageSection { Start = 0x1000, Length = 0x1ff000, Executable = true }); image.Sections.Add(new ImageSection { Start = 0x200000, Length = 0x300000, Executable = false });
            string legacy = System.Text.RegularExpressions.Regex.Replace(current, Ini.Pattern(version), ""); legacy = System.Text.RegularExpressions.Regex.Replace(legacy, Ini.Pattern(version + "-SLInit"), "");
            legacy = System.Text.RegularExpressions.Regex.Replace(legacy, "(?m)^(?:CDefPolicy_Query_r9d_rdi_jmp|mov_eax_1_nop_2)=.*\\r?\\n", "");
            try {
                Test("Original x64 DLL fingerprint", () => Assert(Files.Hash(payload.Wrapper) == "798AF20DB39280F90A1D35F2AC2C1D62124D1F5218A2A0FA29D87A13340BD3E4", "Wrong DLL"));
                Test("Original x86 DLL fingerprint", () => Assert(PeImage.Read(Resources.Payload("x86").Wrapper).Architecture == "x86", "Wrong architecture"));
                Test("Real catalog-signed Windows DLL verifies", () => Assert(Trust.Valid(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "termsrv.dll")), "System catalog membership did not verify"));
                Test("Modified catalog member is rejected", () => {
                    var fake = Fixture(payload, current, image); byte[] bytes = File.ReadAllBytes(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "termsrv.dll")); bytes[0x1000] ^= 1; File.WriteAllBytes(fake.TermsrvPath, bytes);
                    Assert(!Trust.Valid(fake.TermsrvPath), "Modified system binary trusted");
                });
                Test("Native fixed version matches raw PE version resource", () => {
                    string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "termsrv.dll"); byte[] bytes = File.ReadAllBytes(path); string raw = null;
                    for (int i = 0; i < bytes.Length - 52; i++) if (BitConverter.ToUInt32(bytes, i) == 0xFEEF04BD && BitConverter.ToUInt32(bytes, i + 4) == 0x10000) { uint ms = BitConverter.ToUInt32(bytes, i + 8), ls = BitConverter.ToUInt32(bytes, i + 12); raw = string.Format("{0}.{1}.{2}.{3}", ms >> 16, ms & 65535, ls >> 16, ls & 65535); break; }
                    Assert(raw != null && Native.FixedVersion(path) == raw, "Compatibility/MUI version rather than fixed resource selected");
                });
                Test("Task Scheduler template is SYSTEM, protected EXE, boot and hourly", () => {
                    var xml = new System.Xml.XmlDocument(); xml.LoadXml(TaskInstaller.Plan()); var ns = new System.Xml.XmlNamespaceManager(xml.NameTable); ns.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task");
                    Assert(xml.SelectSingleNode("//t:Principal/t:UserId", ns).InnerText == "S-1-5-18", "Wrong task account");
                    Assert(xml.SelectSingleNode("//t:BootTrigger/t:Delay", ns).InnerText == "PT2M", "Wrong boot delay");
                    Assert(xml.SelectSingleNode("//t:TimeTrigger/t:Repetition/t:Interval", ns).InnerText == "PT1H", "Wrong repeat interval");
                    Assert(xml.SelectSingleNode("//t:TimeTrigger/t:Repetition/t:Duration", ns) == null, "Repeat should be indefinite");
                    Assert(xml.SelectSingleNode("//t:MultipleInstancesPolicy", ns).InnerText == "IgnoreNew", "Overlapping runs permitted");
                    Assert(xml.SelectSingleNode("//t:Exec/t:Arguments", ns).InnerText == "--auto", "Wrong task mode");
                    Assert(xml.SelectSingleNode("//t:Exec/t:Command", ns).InnerText.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase), "Task runs from a user-writable download folder");
                });
                Test("Exact numeric build validates", () => Ini.Parse(current).Validate(version, image));
                Test("Unknown exact build rejected", () => Reject(() => Ini.Parse(current).Validate("10.0.26100.99999", image)));
                Test("Duplicate sections rejected", () => Reject(() => Ini.Parse(current + "\r\n[" + version + "]\r\nx=1\r\n")));
                Test("Bad RVA rejected", () => Reject(() => Ini.Parse(current.Replace("SLInitOffset.x64=BA448", "SLInitOffset.x64=FFFFFFFF")).Validate(version, image)));
                Test("Shared patch conflict rejected", () => Reject(() => Ini.Merge(legacy.Replace("jmpshort=EB", "jmpshort=90"), current, version, image, new List<string>())));
                Test("Merge is minimal and idempotent", () => {
                    var changes = new List<string>(); string merged = Ini.Merge(legacy, current, version, image, changes); Assert(changes.Count == 4, "Expected 2 definitions and 2 sections");
                    var again = new List<string>(); Assert(Ini.Merge(merged, current, version, image, again) == merged && again.Count == 0, "Repeated merge changed bytes");
                    Assert(Ini.SectionText(merged, "Main") == Ini.SectionText(legacy, "Main"), "Global settings changed");
                });
                Test("Disconnected unknown-protocol session blocks", () => Assert(new Session { State = "Disconnected", Station = "", Protocol = -1 }.Blocks, "Disconnected session not blocked"));
                Test("Console does not block", () => Assert(!new Session { State = "Active", Station = "Console", Protocol = 0 }.Blocks, "Console blocked"));
                Test("Stopped service uses independent LSA verification", () => {
                    var sessions = SessionGuard.Read(() => { throw new IOException("WTS unavailable"); }, () => true, () => new List<Session> { Remote("Disconnected") }); Assert(sessions.Count == 1 && sessions[0].Blocks, "Remote logon missed by fallback");
                });
                Test("Running service never hides WTS read failure", () => {
                    bool lsaCalled = false, threw = false; try { SessionGuard.Read(() => { throw new IOException("WTS unavailable"); }, () => false, () => { lsaCalled = true; return new List<Session>(); }); } catch (IOException) { threw = true; } Assert(threw && !lsaCalled, "WTS failure ignored");
                });
                Test("Unavailable WTS and LSA fail closed", () => {
                    bool threw = false; try { SessionGuard.Read(() => { throw new IOException("WTS unavailable"); }, () => true, () => { throw new IOException("LSA unavailable"); }); } catch (IOException) { threw = true; } Assert(threw, "Unreadable logons accepted");
                });
                Test("Ambiguous LSA non-console logon blocks", () => Assert(new Session { Id = 4, State = "LogonPresent", Station = "LSA-non-console", Protocol = 0 }.Blocks, "Ambiguous logon ignored"));
                Test("Healthy no-op does not fetch or restart", () => {
                    var fake = Fixture(payload, current, image); string hash = Files.HashFile(fake.IniPath); var engine = EngineFor(fake, payload); Assert(engine.Run() == 0 && fake.Stops == 0 && fake.Starts == 0 && fake.Registrations == 0 && Files.HashFile(fake.IniPath) == hash && !(bool)engine.Report["NetworkUsed"], "No-op mutated host");
                });
                Test("Build update changes only INI with one reload", () => {
                    var fake = Fixture(payload, legacy, image); string dllHash = Files.HashFile(fake.WrapperPath); var engine = EngineFor(fake, payload); Assert(engine.Run() == 0 && fake.Starts == 1 && fake.Stops == 1 && Files.HashFile(fake.WrapperPath) == dllHash, Program.Json.Serialize(engine.Report));
                    Assert(Ini.SectionText(Files.Text(fake.IniPath), "Main") == Ini.SectionText(legacy, "Main"), "Global settings changed");
                });
                Test("Valid-PE but corrupted DLL is restored", () => {
                    var fake = Fixture(payload, current, image); byte[] damaged = File.ReadAllBytes(fake.WrapperPath); damaged[damaged.Length - 1] ^= 1; File.WriteAllBytes(fake.WrapperPath, damaged);
                    var engine = EngineFor(fake, payload); Assert(engine.Run() == 0 && fake.Starts == 1 && Files.HashFile(fake.WrapperPath) == Files.Hash(payload.Wrapper) && (bool)engine.Report["RecoveredLibrary"], Program.Json.Serialize(engine.Report));
                });
                Test("Missing DLL is restored", () => {
                    var fake = Fixture(payload, current, image); File.Delete(fake.WrapperPath); fake.Runtime = "NotLoaded"; var engine = EngineFor(fake, payload); Assert(engine.Run() == 0 && Files.HashFile(fake.WrapperPath) == Files.Hash(payload.Wrapper), Program.Json.Serialize(engine.Report));
                });
                Test("Missing INI is reconstructed", () => {
                    var fake = Fixture(payload, current, image); File.Delete(fake.IniPath); var engine = EngineFor(fake, payload); Assert(engine.Run() == 0 && File.Exists(fake.IniPath), Program.Json.Serialize(engine.Report));
                });
                Test("Update reset registration is repaired", () => {
                    var fake = Fixture(payload, current, image); fake.Registered = false; fake.ServiceDll = fake.TermsrvPath; fake.Runtime = "NotLoaded";
                    var engine = EngineFor(fake, payload); Assert(engine.Run() == 0 && fake.Registrations == 1 && fake.ServiceDll == fake.WrapperPath, Program.Json.Serialize(engine.Report));
                });
                Test("Fresh install restores files and registration", () => {
                    var fake = Fixture(payload, current, image); File.Delete(fake.IniPath); File.Delete(fake.WrapperPath); fake.Registered = false; fake.ServiceDll = fake.TermsrvPath; fake.Runtime = "NotLoaded";
                    var engine = EngineFor(fake, payload); Assert(engine.Run() == 0 && fake.Registrations == 1 && fake.Starts == 1 && File.Exists(fake.IniPath) && File.Exists(fake.WrapperPath), Program.Json.Serialize(engine.Report));
                });
                Test("Unloaded registered DLL reloads without file update", () => {
                    var fake = Fixture(payload, current, image); fake.Runtime = "NotLoaded"; var engine = EngineFor(fake, payload); Assert(engine.Run() == 0 && fake.Starts == 1 && !(bool)engine.Report["Applied"], Program.Json.Serialize(engine.Report));
                });
                Test("Reload-only failure restores running service without file writes", () => {
                    var fake = Fixture(payload, current, image); fake.Runtime = "NotLoaded"; fake.FailFirstStart = true; string iniHash = Files.HashFile(fake.IniPath), dllHash = Files.HashFile(fake.WrapperPath); var engine = EngineFor(fake, payload);
                    Assert(engine.Run() == 2 && fake.Running && fake.Starts == 2 && iniHash == Files.HashFile(fake.IniPath) && dllHash == Files.HashFile(fake.WrapperPath) && (bool)engine.Report["ServiceStateRestored"] && !engine.Report.ContainsKey("Backup"), Program.Json.Serialize(engine.Report));
                });
                Test("Failed start of previously stopped service restores stopped state", () => {
                    var fake = Fixture(payload, current, image); fake.Running = false; fake.Listener = false; fake.Runtime = "Stopped"; fake.FailFirstStart = true; var engine = EngineFor(fake, payload);
                    Assert(engine.Run() == 2 && !fake.Running && fake.Starts == 1 && (bool)engine.Report["ServiceStateRestored"], Program.Json.Serialize(engine.Report));
                });
                Test("Active remote prevents INI writes and reload", () => {
                    var fake = Fixture(payload, legacy, image); fake.Sessions.Add(Remote("Active")); string hash = Files.HashFile(fake.IniPath); var engine = EngineFor(fake, payload);
                    Assert(engine.Run() == 3 && fake.Stops == 0 && fake.Starts == 0 && hash == Files.HashFile(fake.IniPath), "Remote session was disturbed");
                });
                Test("Disconnected remote prevents DLL restoration", () => {
                    var fake = Fixture(payload, current, image); File.Delete(fake.WrapperPath); fake.Sessions.Add(Remote("Disconnected")); var engine = EngineFor(fake, payload); Assert(engine.Run() == 3 && !File.Exists(fake.WrapperPath) && fake.Stops == 0, "Disconnected session was ignored");
                });
                Test("Remote arriving during preparation blocks write", () => {
                    var fake = Fixture(payload, legacy, image); fake.RemoteAtGuard = 3; string hash = Files.HashFile(fake.IniPath); var engine = EngineFor(fake, payload);
                    Assert(engine.Run() == 3 && fake.Stops == 0 && hash == Files.HashFile(fake.IniPath), Program.Json.Serialize(engine.Report));
                });
                Test("Unreadable sessions fail closed", () => {
                    var fake = Fixture(payload, legacy, image); fake.SessionError = "Simulated WTS error"; var engine = EngineFor(fake, payload); Assert(engine.Run() == 2 && fake.Stops == 0, "Unverifiable sessions allowed repair");
                });
                Test("Unattended non-admin never elevates", () => {
                    var fake = Fixture(payload, legacy, image); fake.IsAdmin = false; var engine = EngineFor(fake, payload); Assert(engine.Run() == 4 && fake.Stops == 0, "Mutation without admin");
                });
                Test("Unreadable stopped service requires admin before recovery", () => {
                    var fake = Fixture(payload, legacy, image); fake.IsAdmin = false; fake.Running = false; fake.SessionError = "Access to LSA denied"; var engine = EngineFor(fake, payload); Assert(engine.Run() == 4 && fake.Stops == 0, "Admin requirement hidden behind unavailable RPC");
                });
                Test("Unknown build does not replace files or register", () => {
                    var fake = Fixture(payload, legacy, image); fake.Version = "10.0.26100.99999"; string hash = Files.HashFile(fake.IniPath); var engine = EngineFor(fake, payload);
                    Assert(engine.Run() == 2 && fake.Stops == 0 && fake.Registrations == 0 && hash == Files.HashFile(fake.IniPath), "Unknown build guessed");
                });
                Test("System signature failure prevents repair", () => {
                    var fake = Fixture(payload, legacy, image); fake.Signed = false; var engine = EngineFor(fake, payload); Assert(engine.Run() == 2 && fake.Stops == 0, "Untrusted system DLL accepted");
                });
                Test("Concurrent Windows Update cancels preparation", () => {
                    var fake = Fixture(payload, legacy, image); fake.ChangeTermsrvAtGuard = 2; string hash = Files.HashFile(fake.IniPath); var engine = EngineFor(fake, payload);
                    Assert(engine.Run() == 2 && fake.Stops == 0 && hash == Files.HashFile(fake.IniPath), "Version race ignored");
                });
                Test("Failed restart rolls back original INI", () => {
                    var fake = Fixture(payload, legacy, image); fake.FailFirstStart = true; string hash = Files.HashFile(fake.IniPath); var engine = EngineFor(fake, payload);
                    Assert(engine.Run() == 2 && engine.Report.ContainsKey("RolledBack") && (bool)engine.Report["RolledBack"] && hash == Files.HashFile(fake.IniPath) && fake.Starts == 2, Program.Json.Serialize(engine.Report));
                });
                Test("Changed INI while stopping service is not overwritten", () => {
                    var fake = Fixture(payload, legacy, image); fake.ChangeIniDuringStop = true; var engine = EngineFor(fake, payload); Assert(engine.Run() == 2 && Files.Text(fake.IniPath).EndsWith("; external edit\r\n") && fake.Starts == 1, Program.Json.Serialize(engine.Report));
                });
                Test("Diagnosis never modifies broken host", () => {
                    var fake = Fixture(payload, legacy, image); var engine = EngineFor(fake, payload, true); Assert(engine.Run() == 1 && fake.Starts == 0 && fake.Stops == 0, "Check mutated host");
                });
                Test("Healthy observed concurrent sessions tolerate module access limits", () => {
                    var fake = Fixture(payload, current, image); fake.Runtime = "Unknown"; fake.IsAdmin = false; fake.Sessions.Add(Remote("Active")); var engine = EngineFor(fake, payload); Assert(engine.Run() == 0 && fake.Stops == 0, "Working host disturbed");
                });
                Test("Unreadable modules do not trigger speculative restart", () => {
                    var fake = Fixture(payload, current, image); fake.Runtime = "Unknown"; var engine = EngineFor(fake, payload); Assert(engine.Run() == 1 && fake.Stops == 0, "Blind restart");
                });
                Test("Malformed installed INI stops before contacting sources", () => {
                    var fake = Fixture(payload, current + "\r\n[Main]\r\nx=1\r\n", image); var engine = EngineFor(fake, payload); Assert(engine.Run() == 2 && fake.Stops == 0 && !(bool)engine.Report["NetworkUsed"], "Malformed configuration was replaced");
                });
                Test("Old pending marker after reboot does not trigger reload", () => {
                    var fake = Fixture(payload, current, image); fake.ProcessStarted = DateTime.UtcNow; PendingMarker(fake, DateTime.UtcNow.AddHours(-1)); var engine = EngineFor(fake, payload); Assert(engine.Run() == 0 && fake.Stops == 0 && fake.Starts == 0, "Unnecessary reload after reboot");
                });
                Test("Pending applied INI is reloaded once and marker removed", () => {
                    var fake = Fixture(payload, current, image); fake.ProcessStarted = DateTime.UtcNow.AddHours(-1); PendingMarker(fake, DateTime.UtcNow); var engine = EngineFor(fake, payload); Assert(engine.Run() == 0 && fake.Starts == 1 && !File.Exists(Path.Combine(fake.Root, "logs", "pending-reload.json")), Program.Json.Serialize(engine.Report));
                });
                Console.WriteLine(passed + " passed; " + failed + " failed. All service actions mocked; only temporary fixture files changed."); return failed == 0 ? 0 : 2;
            } finally {
                foreach (string root in roots) {
                    string full = Path.GetFullPath(root), parent = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
                    if (!Path.GetDirectoryName(full).Equals(parent, StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(full).StartsWith("rdpwrap-maint-test-", StringComparison.Ordinal)) throw new Exception("Refusing cleanup outside test directory");
                    Directory.Delete(full, true);
                }
            }
        }
        static Session Remote(string state) { return new Session { Id = 1, State = state, Station = state == "Active" ? "RDP-Tcp#0" : "", Protocol = state == "Active" ? 2 : -1, User = "fixture-remote" }; }
        static FakePlatform Fixture(Payload payload, string ini, PeImage image) {
            string root = Path.Combine(Path.GetTempPath(), "rdpwrap-maint-test-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(root); roots.Add(root);
            var fake = new FakePlatform { Root = root, Image = image }; File.WriteAllBytes(fake.WrapperPath, payload.Wrapper); File.WriteAllText(fake.IniPath, ini, Files.Utf8);
            // A synthetic system DLL keeps tests independent of the Windows build
            // executing them. The core never writes it; the race test changes its
            // fixture bytes through the fake platform, not Windows APIs.
            File.WriteAllBytes(fake.TermsrvPath, new byte[256]); fake.ServiceDll = fake.WrapperPath; return fake;
        }
        static Engine EngineFor(FakePlatform fake, Payload payload, bool check = false) { string logs = Path.Combine(fake.Root, "logs"); Directory.CreateDirectory(logs); return new Engine(fake, payload, new Options { LogDirectory = logs, CheckOnly = check }, url => { throw new IOException("Network disabled in tests"); }); }
        static void PendingMarker(FakePlatform fake, DateTime applied) { string logs = Path.Combine(fake.Root, "logs"); Directory.CreateDirectory(logs); File.WriteAllText(Path.Combine(logs, "pending-reload.json"), Program.Json.Serialize(new Dictionary<string, object> { { "Version", fake.Version }, { "IniHash", Files.HashFile(fake.IniPath) }, { "WrapperHash", Files.HashFile(fake.WrapperPath) }, { "AppliedUtc", applied.ToString("o") } })); }
        sealed class FakePlatform : IPlatform {
            public string Root, ServiceDll, Runtime = "Loaded", Version = "10.0.26100.9444", SessionError;
            public bool IsAdmin = true, Registered = true, Running = true, Listener = true, Signed = true, FailFirstStart, ChangeIniDuringStop;
            public int Stops, Starts, Registrations, Guards, RemoteAtGuard, ChangeTermsrvAtGuard; public PeImage Image;
            public DateTime? ProcessStarted;
            public List<Session> Sessions = new List<Session> { new Session { Id = 2, User = "fixture-local", State = "Active", Station = "Console", Protocol = 0 } };
            public string WrapperPath { get { return Path.Combine(Root, "rdpwrap.dll"); } } public string IniPath { get { return Path.Combine(Root, "rdpwrap.ini"); } } public string TermsrvPath { get { return Path.Combine(Root, "termsrv.dll"); } }
            public Snapshot Read() { return new Snapshot { Version = Version, Architecture = "x64", Image = Image, TermsrvPath = TermsrvPath, TermsrvHash = Files.HashFile(TermsrvPath), ServiceDll = ServiceDll, WrapperPath = WrapperPath, IniPath = IniPath, WrapperHash = Files.HashFile(WrapperPath), IniHash = Files.HashFile(IniPath), Registered = Registered, IsAdmin = IsAdmin, ServiceRunning = Running, SignedTermsrv = Signed, Listener = Listener, RdpEnabled = true, Runtime = Runtime, Sessions = Sessions.ToList(), SessionError = SessionError, ProcessStarted = ProcessStarted }; }
            public void GuardSessions() { Guards++; if (RemoteAtGuard == Guards) Sessions.Add(Remote("Active")); if (ChangeTermsrvAtGuard == Guards) File.AppendAllText(TermsrvPath, "update"); if (SessionError != null) throw new IOException(SessionError); if (Sessions.Any(s => s.Blocks)) throw new MaintenanceException("Fixture remote session", 3); }
            public void Register(string path) { GuardSessions(); ServiceDll = path; Registered = path == WrapperPath; Registrations++; }
            public void StopService() { GuardSessions(); Stops++; Running = false; Listener = false; Runtime = "Stopped"; if (ChangeIniDuringStop) File.AppendAllText(IniPath, "; external edit\r\n"); }
            public void StartService() { GuardSessions(); Starts++; if (FailFirstStart && Starts == 1) throw new IOException("Simulated service start failure"); Running = true; Listener = true; Runtime = Registered ? "Loaded" : "NotLoaded"; }
        }
    }
}
