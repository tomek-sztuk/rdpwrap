// SPDX-License-Identifier: Apache-2.0
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace RdpWrapMaintenance {
    public static class Program {
        public static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 8 * 1024 * 1024 };
        public static int Main(string[] args) {
            var options = new Options(); bool command = false, selfTest = false, register = false, remove = false;
            try {
                for (int i = 0; i < args.Length; i++) {
                    switch (args[i]) {
                        case "--auto": case "-a": command = true; break;
                        case "--check": command = true; options.CheckOnly = true; break;
                        case "--self-test": selfTest = true; break;
                        case "--register-task": register = true; break;
                        case "--unregister-task": remove = true; break;
                        case "--source": if (++i == args.Length) throw new MaintenanceException("--source requires a local INI path"); options.SourceFile = Path.GetFullPath(args[i]); break;
                        case "--log-dir": if (++i == args.Length) throw new MaintenanceException("--log-dir requires a directory"); options.LogDirectory = Path.GetFullPath(args[i]); break;
                        case "--help": case "-h": Help(); return 0;
                        case "--license": Console.WriteLine(Resources.License()); return 0;
                        case "--task-plan": Console.WriteLine(TaskInstaller.Plan()); return 0;
                        default: throw new MaintenanceException("Unknown argument: " + args[i]);
                    }
                }
                if (selfTest) { if (command || register || remove || options.SourceFile != null || options.LogDirectory != null) throw new MaintenanceException("--self-test cannot be combined with other operations"); return SelfTest.Run(); }
                if (register || remove) {
                    if ((register && remove) || command || options.SourceFile != null || options.LogDirectory != null) throw new MaintenanceException("Task registration is a separate operation");
                    if (!WindowsPlatform.Administrator) throw new MaintenanceException("Task registration requires administrator privileges", 4);
                    TaskInstaller.Configure(remove); return 0;
                }
                if (!command) { Help(); return 1; }
                if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess) throw new MaintenanceException("Run the AnyCPU/x64 build on 64-bit Windows");
                if (options.LogDirectory == null) {
                    options.LogDirectory = DefaultLogs();
                    if (WindowsPlatform.Administrator) TaskInstaller.ProtectDirectory(options.LogDirectory);
                }
                Directory.CreateDirectory(options.LogDirectory);
                foreach (string component in new[] { options.LogDirectory, Path.Combine(options.LogDirectory, "backups"), Path.Combine(options.LogDirectory, "pending-reload.json") })
                    if ((Directory.Exists(component) || File.Exists(component)) && (File.GetAttributes(component) & FileAttributes.ReparsePoint) != 0) throw new MaintenanceException("Maintenance data must not be a junction or symbolic link");
                bool owned = false;
                using (var mutex = new Mutex(false, @"Global\CodexRdpWrapperMaintenance")) {
                    try {
                        try { owned = mutex.WaitOne(0); } catch (AbandonedMutexException) { owned = true; }
                        if (!owned) { Console.WriteLine("Held: another maintenance operation is running"); return 3; }
                        var platform = new WindowsPlatform(); var snapshot = platform.Read();
                        var engine = new Engine(platform, Resources.Payload(snapshot.Architecture), options, Download);
                        int code = engine.Run();
                        string path = Path.Combine(options.LogDirectory, "native-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".json");
                        File.WriteAllText(path, Json.Serialize(engine.Report), Files.Utf8);
                        Console.WriteLine("RDP Wrapper: " + engine.Report["State"]);
                        object libraryMatches; engine.Report.TryGetValue("LibraryMatchesBundle", out libraryMatches);
                        Console.WriteLine("Termsrv: " + snapshot.Version + " | DLL: " + (libraryMatches ?? "Unknown") + " | runtime: " + snapshot.Runtime);
                        object error; if (engine.Report.TryGetValue("Error", out error)) Console.WriteLine(error);
                        Console.WriteLine("Raport: " + path);
                        if (code == 0) Console.WriteLine("Test lokalny nie sprawdza logowania z LAN ani jakosci obrazu.");
                        return code;
                    } finally { if (owned) mutex.ReleaseMutex(); }
                }
            } catch (Exception e) {
                Console.Error.WriteLine(e.Message); var known = e as MaintenanceException; return known == null ? 2 : known.ExitCode;
            }
        }
        static string DefaultLogs() {
            if (WindowsPlatform.Administrator) return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RDPWrapperMaintenance");
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RDPWrapperMaintenance");
        }
        public static string Download(string url) {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var request = (HttpWebRequest)WebRequest.Create(url); request.Timeout = request.ReadWriteTimeout = 25000; request.AllowAutoRedirect = false; request.UserAgent = "RDPWrapMaintenance/1.0";
            using (var response = (HttpWebResponse)request.GetResponse()) {
                if (response.StatusCode != HttpStatusCode.OK || response.ContentLength > 8 * 1024 * 1024) throw new MaintenanceException("Unexpected source response");
                using (var stream = response.GetResponseStream()) using (var result = new MemoryStream()) {
                    byte[] buffer = new byte[8192]; int n;
                    while ((n = stream.Read(buffer, 0, buffer.Length)) != 0) { result.Write(buffer, 0, n); if (result.Length > 8 * 1024 * 1024) throw new MaintenanceException("Source exceeds size limit"); }
                    return Files.Utf8.GetString(result.ToArray());
                }
            }
        }
        static void Help() {
            Console.WriteLine("RDP Wrapper Maintenance - unattended installer and repair (Windows 10/11)");
            Console.WriteLine("RDPWMaint.exe --check                    Read-only diagnosis");
            Console.WriteLine("RDPWMaint.exe --auto [--source file.ini]  Install/repair only when necessary");
            Console.WriteLine("RDPWMaint.exe --register-task            Admin: protected copy + SYSTEM task");
            Console.WriteLine("RDPWMaint.exe --unregister-task          Admin: remove only this task");
            Console.WriteLine("RDPWMaint.exe --task-plan                Preview task XML; registers nothing");
            Console.WriteLine("RDPWMaint.exe --self-test                Tests use temporary fixtures, never services");
            Console.WriteLine("Codes: 0 healthy; 1 diagnosis needs attention; 2 failure; 3 held; 4 admin required.");
            Console.WriteLine("Active/disconnected remote sessions block changes. No UAC, reboot, binary downloads,");
            Console.WriteLine("system DLL replacement, firewall, graphics or authentication changes.");
        }
    }
    public static class Resources {
        public static string License() { return Files.Utf8.GetString(Read("License")); }
        static byte[] Read(string name) {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)) {
                if (stream == null) throw new MaintenanceException("Missing embedded resource: " + name);
                using (var memory = new MemoryStream()) { stream.CopyTo(memory); return memory.ToArray(); }
            }
        }
        static string Identifier(BinaryReader reader, long end) {
            if (reader.BaseStream.Position + 2 > end) throw new MaintenanceException("Invalid resource identifier");
            ushort first = reader.ReadUInt16(); if (first == 0xffff) { if (reader.BaseStream.Position + 2 > end) throw new MaintenanceException("Invalid resource ID"); return "#" + reader.ReadUInt16(); }
            var result = new StringBuilder(); ushort c = first;
            while (c != 0) { result.Append((char)c); if (reader.BaseStream.Position + 2 > end) throw new MaintenanceException("Unterminated resource name"); c = reader.ReadUInt16(); } return result.ToString();
        }
        static byte[] Wrapper(string name) {
            byte[] bytes = Read("WrapperBundle");
            using (var stream = new MemoryStream(bytes)) using (var reader = new BinaryReader(stream)) {
                int records = 0;
                while (stream.Position + 8 <= stream.Length) {
                    if (++records > 2048) throw new MaintenanceException("Resource record limit exceeded");
                    long start = stream.Position; uint size = reader.ReadUInt32(), header = reader.ReadUInt32();
                    long body = start + header, end = body + size;
                    if (header < 8 || body > stream.Length || end > stream.Length) throw new MaintenanceException("Invalid resource bounds");
                    string type = Identifier(reader, body), id = Identifier(reader, body);
                    if (type == "#10" && id.Equals(name, StringComparison.OrdinalIgnoreCase)) { if (size == 0 || size > 8 * 1024 * 1024) throw new MaintenanceException("Invalid DLL resource size"); stream.Position = body; return reader.ReadBytes((int)size); }
                    stream.Position = (end + 3) & ~3L;
                }
            }
            throw new MaintenanceException("DLL resource not found: " + name);
        }
        public static Payload Payload(string architecture) {
            if (architecture != "x64" && architecture != "x86") throw new MaintenanceException("Unsupported architecture");
            byte[] dll = Wrapper(architecture == "x64" ? "rdpw64" : "rdpw32");
            string expected = architecture == "x64" ? "798AF20DB39280F90A1D35F2AC2C1D62124D1F5218A2A0FA29D87A13340BD3E4" : "861AD4BBF682B35AFFDA23FAB92C8DB945F3FA34F78177843C87802D1FD02020";
            if (Files.Hash(dll) != expected || PeImage.Read(dll).Architecture != architecture) throw new MaintenanceException("Original embedded Wrapper fingerprint does not match");
            return new Payload { Wrapper = dll, DefaultIni = Files.Utf8.GetString(Read("DefaultIni")) };
        }
    }
    public static class TaskInstaller {
        const string TaskName = "RDP Wrapper Maintenance";
        static dynamic Scheduler() {
            Type type = Type.GetTypeFromProgID("Schedule.Service"); if (type == null) throw new MaintenanceException("Windows Task Scheduler is unavailable");
            dynamic scheduler = Activator.CreateInstance(type); scheduler.Connect(); return scheduler;
        }
        static dynamic Definition(dynamic scheduler, string target) {
            dynamic task = scheduler.NewTask(0); task.RegistrationInfo.Description = "Check and repair RDP Wrapper after Windows Update. Remote sessions block changes.";
            task.Principal.UserId = "S-1-5-18"; task.Principal.LogonType = 5; task.Principal.RunLevel = 1;
            task.Settings.MultipleInstances = 2; task.Settings.StartWhenAvailable = true; task.Settings.DisallowStartIfOnBatteries = false; task.Settings.StopIfGoingOnBatteries = false; task.Settings.ExecutionTimeLimit = "PT10M";
            dynamic boot = task.Triggers.Create(8); boot.Delay = "PT2M";
            dynamic timer = task.Triggers.Create(1); timer.StartBoundary = DateTime.Now.AddMinutes(5).ToString("s"); timer.Repetition.Interval = "PT1H"; timer.Repetition.StopAtDurationEnd = false;
            dynamic action = task.Actions.Create(0); action.Path = target; action.Arguments = "--auto"; action.WorkingDirectory = Path.GetDirectoryName(target);
            return task;
        }
        public static string Plan() {
            dynamic scheduler = Scheduler();
            return (string)Definition(scheduler, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RDP Wrapper Maintenance", "RDPWMaint.exe")).XmlText;
        }
        public static void ProtectDirectory(string directory) {
            if (Directory.Exists(directory) && (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) throw new MaintenanceException("Managed directory must not be a junction or symbolic link");
            Directory.CreateDirectory(directory);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null); var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null); var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var acl = new DirectorySecurity(); acl.SetOwner(admins); acl.SetAccessRuleProtection(true, false);
            foreach (var sid in new[] { admins, system }) acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow)); Directory.SetAccessControl(directory, acl);
        }
        public static void Configure(bool remove) {
            dynamic scheduler = Scheduler(); dynamic folder = scheduler.GetFolder("\\");
            if (remove) { folder.DeleteTask(TaskName, 0); Console.WriteLine("Removed task: " + TaskName); return; }
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RDP Wrapper Maintenance");
            ProtectDirectory(directory);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            string self = Assembly.GetExecutingAssembly().Location, target = Path.Combine(directory, "RDPWMaint.exe");
            if (File.Exists(target) && (File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0) throw new MaintenanceException("Task executable must not be a link");
            if (!self.Equals(target, StringComparison.OrdinalIgnoreCase)) File.Copy(self, target, true);
            var fileAcl = new FileSecurity(); fileAcl.SetOwner(admins); fileAcl.SetAccessRuleProtection(false, false); File.SetAccessControl(target, fileAcl);
            dynamic task = Definition(scheduler, target);
            folder.RegisterTaskDefinition(TaskName, task, 6, "S-1-5-18", null, 5, null);
            Console.WriteLine("Registered SYSTEM task: boot + every hour. Executable: " + target);
        }
    }
}
