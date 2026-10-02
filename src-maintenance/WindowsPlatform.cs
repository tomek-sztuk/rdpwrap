// SPDX-License-Identifier: Apache-2.0
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;

namespace RdpWrapMaintenance {
    public sealed class WindowsPlatform : IPlatform {
        readonly List<string> dependencies = new List<string>();
        public static bool Administrator { get { using (var identity = WindowsIdentity.GetCurrent()) return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); } }
        static RegistryKey Open(string path, bool writable) { using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32)) { var key = root.OpenSubKey(path, writable); if (key == null) throw new MaintenanceException("Missing registry key: " + path); return key; } }
        public Snapshot Read() {
            string system = Environment.GetFolderPath(Environment.SpecialFolder.System), termsrv = Path.Combine(system, "termsrv.dll"), serviceDll;
            using (var key = Open(@"SYSTEM\CurrentControlSet\Services\TermService\Parameters", false)) serviceDll = Environment.ExpandEnvironmentVariables(Convert.ToString(key.GetValue("ServiceDll", null, RegistryValueOptions.DoNotExpandEnvironmentNames)));
            string library = Path.GetFileName(serviceDll);
            if (!string.Equals(library, "rdpwrap.dll", StringComparison.OrdinalIgnoreCase) && !string.Equals(library, "termsrv.dll", StringComparison.OrdinalIgnoreCase)) throw new MaintenanceException("Another TermService library is registered; refusing replacement");
            bool registered = string.Equals(library, "rdpwrap.dll", StringComparison.OrdinalIgnoreCase);
            string wrapper = registered ? serviceDll : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RDP Wrapper", "rdpwrap.dll");
            string standardWrapper = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RDP Wrapper", "rdpwrap.dll");
            if (!wrapper.Equals(standardWrapper, StringComparison.OrdinalIgnoreCase) && !wrapper.Equals(Path.Combine(system, "rdpwrap.dll"), StringComparison.OrdinalIgnoreCase)) throw new MaintenanceException("Nonstandard Wrapper location; refusing an unattended privileged write");
            var image = PeImage.Read(File.ReadAllBytes(termsrv));
            var s = new Snapshot { Version = Native.FixedVersion(termsrv), TermsrvPath = termsrv, TermsrvHash = Files.HashFile(termsrv), Architecture = image.Architecture, Image = image, ServiceDll = serviceDll, Registered = registered, WrapperPath = wrapper, IniPath = Path.Combine(Path.GetDirectoryName(wrapper), "rdpwrap.ini"), IsAdmin = Administrator, SignedTermsrv = Trust.Valid(termsrv) };
            s.WrapperHash = Files.HashFile(s.WrapperPath); s.IniHash = Files.HashFile(s.IniPath);
            using (var key = Open(@"SYSTEM\CurrentControlSet\Control\Terminal Server", false)) s.RdpEnabled = Convert.ToInt32(key.GetValue("fDenyTSConnections", 1)) == 0;
            int port; using (var key = Open(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", false)) port = Convert.ToInt32(key.GetValue("PortNumber", 3389));
            using (var service = new ServiceController("TermService")) s.ServiceRunning = service.Status == ServiceControllerStatus.Running;
            s.ProcessId = ServiceProcessId(); s.Runtime = s.ServiceRunning ? "Unknown" : "Stopped";
            if (s.ProcessId != 0) {
                bool debug = false;
                try {
                    if (s.IsAdmin) { Process.EnterDebugMode(); debug = true; }
                    using (var process = Process.GetProcessById(s.ProcessId)) {
                        s.ProcessStarted = process.StartTime.ToUniversalTime();
                        var modules = process.Modules.Cast<ProcessModule>().Where(m => !string.IsNullOrEmpty(m.ModuleName)).ToArray();
                        if (modules.Length < 2) throw new MaintenanceException("Process modules are not readable");
                        var dll = modules.Where(m => m.ModuleName.Equals("rdpwrap.dll", StringComparison.OrdinalIgnoreCase)).ToArray();
                        if (dll.Length > 1) throw new MaintenanceException("Multiple Wrapper modules found");
                        s.Runtime = dll.Length == 0 ? "NotLoaded" : dll[0].FileName.Equals(wrapper, StringComparison.OrdinalIgnoreCase) ? "Loaded" : "LoadedDifferentPath";
                    }
                } catch (Exception e) { s.RuntimeError = e.Message; }
                finally { if (debug) Process.LeaveDebugMode(); }
            }
            s.Listener = Listener(port);
            try { s.Sessions = Sessions(); } catch (Exception e) { s.SessionError = e.Message; }
            return s;
        }
        public void GuardSessions() {
            var sessions = Sessions().Where(s => s.Blocks).ToArray();
            if (sessions.Length != 0) throw new MaintenanceException("Remote sessions block installation, writes and reload: " + string.Join("; ", sessions.Select(s => s.User + " (" + s.Id + ", " + s.State + ")")), 3);
        }
        static List<Session> Sessions() { return SessionGuard.Read(Wts.Read, () => { using (var service = new ServiceController("TermService")) return service.Status == ServiceControllerStatus.Stopped; }, LsaSessions.Read); }
        public void Register(string path) { GuardSessions(); using (var key = Open(@"SYSTEM\CurrentControlSet\Services\TermService\Parameters", true)) key.SetValue("ServiceDll", path, RegistryValueKind.ExpandString); }
        public void StopService() {
            GuardSessions();
            using (var service = new ServiceController("TermService")) {
                foreach (var dependent in service.DependentServices) {
                    using (dependent) {
                        if (dependent.Status == ServiceControllerStatus.Running) {
                            GuardSessions();
                            if (!dependencies.Contains(dependent.ServiceName)) dependencies.Add(dependent.ServiceName);
                            dependent.Stop(); dependent.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                        }
                    }
                }
                service.Refresh();
                if (service.Status == ServiceControllerStatus.Stopped) return;
                if (service.Status == ServiceControllerStatus.StartPending) service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                if (service.Status != ServiceControllerStatus.StopPending) { GuardSessions(); service.Stop(); }
                service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            }
        }
        public void StartService() {
            GuardSessions();
            using (var service = new ServiceController("TermService")) {
                if (service.Status == ServiceControllerStatus.Stopped) service.Start();
                service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            }
            foreach (string name in dependencies) using (var service = new ServiceController(name)) {
                if (service.Status == ServiceControllerStatus.Stopped) service.Start();
                service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            }
            // Starting SCM is not the same as a listening RDP server. Give the
            // listener a bounded chance to initialize; never perform login.
            int port; using (var key = Open(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", false)) port = Convert.ToInt32(key.GetValue("PortNumber", 3389));
            for (int i = 0; i < 10; i++) { if (Listener(port)) return; System.Threading.Thread.Sleep(500); }
        }
        static int ServiceProcessId() {
            IntPtr manager = Native.OpenSCManager(null, null, 1); if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                IntPtr service = Native.OpenService(manager, "TermService", 4); if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                try { Native.ServiceStatus status; int needed; if (!Native.QueryServiceStatusEx(service, 0, out status, Marshal.SizeOf(typeof(Native.ServiceStatus)), out needed)) throw new Win32Exception(Marshal.GetLastWin32Error()); return status.ProcessId; }
                finally { Native.CloseServiceHandle(service); }
            } finally { Native.CloseServiceHandle(manager); }
        }
        public static bool Listener(int port) {
            using (var client = new TcpClient()) {
                try {
                    var connect = client.ConnectAsync("127.0.0.1", port); if (!connect.Wait(3000)) return false; connect.GetAwaiter().GetResult();
                    using (var stream = client.GetStream()) {
                        stream.ReadTimeout = stream.WriteTimeout = 3000;
                        byte[] request = { 3, 0, 0, 19, 14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0 };
                        stream.Write(request, 0, request.Length); byte[] header = Read(stream, 4);
                        int length = header[2] * 256 + header[3]; if (header[0] != 3 || length < 11 || length > 8192) return false;
                        byte[] body = Read(stream, length - 4); return body[1] == 0xd0 && !(body.Length >= 15 && body[7] == 3);
                    }
                } catch { return false; }
            }
        }
        static byte[] Read(Stream stream, int size) { var data = new byte[size]; int read = 0; while (read < size) { int n = stream.Read(data, read, size - read); if (n == 0) throw new IOException("Incomplete RDP negotiation"); read += n; } return data; }
    }
    internal static class Native {
        [DllImport("version.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFileVersionInfoSizeExW(uint flags, string path, out uint handle);
        [DllImport("version.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool GetFileVersionInfoExW(uint flags, string path, uint handle, uint length, byte[] data);
        [DllImport("version.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool VerQueryValueW(IntPtr data, string item, out IntPtr value, out uint length);
        public static string FixedVersion(string path) {
            uint handle; uint size = GetFileVersionInfoSizeExW(2, path, out handle);
            if (size == 0 || size > 1024 * 1024) throw new MaintenanceException("Version resource could not be read");
            var bytes = new byte[size]; if (!GetFileVersionInfoExW(2, path, 0, size, bytes)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try {
                IntPtr value; uint length;
                if (!VerQueryValueW(pinned.AddrOfPinnedObject(), "\\", out value, out length) || length < 52 || unchecked((uint)Marshal.ReadInt32(value)) != 0xFEEF04BD) throw new MaintenanceException("Invalid fixed version information");
                uint ms = unchecked((uint)Marshal.ReadInt32(value, 8)), ls = unchecked((uint)Marshal.ReadInt32(value, 12));
                return string.Format("{0}.{1}.{2}.{3}", ms >> 16, ms & 65535, ls >> 16, ls & 65535);
            } finally { pinned.Free(); }
        }
        [StructLayout(LayoutKind.Sequential)] internal struct ServiceStatus { public int Type, State, Controls, Win32Error, ServiceError, CheckPoint, WaitHint, ProcessId, Flags; }
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern IntPtr OpenSCManager(string computer, string database, int access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern IntPtr OpenService(IntPtr manager, string name, int access);
        [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatus status, int size, out int needed);
        [DllImport("advapi32.dll")] internal static extern bool CloseServiceHandle(IntPtr handle);
    }
    public static class Wts {
        [StructLayout(LayoutKind.Sequential)] struct Info { public int Id; public IntPtr Station; public int State; }
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr data, out int count);
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool WTSQuerySessionInformationW(IntPtr server, int session, int type, out IntPtr data, out int bytes);
        [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr data);
        static string Text(int id, int type) {
            IntPtr data; int bytes; if (!WTSQuerySessionInformationW(IntPtr.Zero, id, type, out data, out bytes)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try { return Marshal.PtrToStringUni(data) ?? ""; } finally { WTSFreeMemory(data); }
        }
        static int Protocol(int id) {
            IntPtr data; int bytes; if (!WTSQuerySessionInformationW(IntPtr.Zero, id, 16, out data, out bytes)) return -1;
            try { return bytes >= 2 ? Marshal.ReadInt16(data) : -1; } finally { WTSFreeMemory(data); }
        }
        public static List<Session> Read() {
            IntPtr data; int count; if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out data, out count)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var result = new List<Session>(); string[] states = { "Active", "Connected", "ConnectQuery", "Shadow", "Disconnected", "Idle", "Listen", "Reset", "Down", "Init" };
            try {
                int size = Marshal.SizeOf(typeof(Info));
                for (int i = 0; i < count; i++) {
                    var s = (Info)Marshal.PtrToStructure(IntPtr.Add(data, i * size), typeof(Info)); if (s.Id == 0 || s.State == 6) continue;
                    string user = Text(s.Id, 5), station = Marshal.PtrToStringUni(s.Station) ?? ""; int protocol = Protocol(s.Id);
                    if (user.Length == 0) { if (protocol != 2 && !station.StartsWith("rdp-", StringComparison.OrdinalIgnoreCase) && s.State != 1 && s.State != 2) continue; user = "(pending logon)"; }
                    string domain = Text(s.Id, 7);
                    result.Add(new Session { Id = s.Id, Protocol = protocol, Station = station, State = s.State >= 0 && s.State < states.Length ? states[s.State] : s.State.ToString(), User = domain.Length == 0 ? user : domain + "\\" + user });
                }
            } finally { WTSFreeMemory(data); }
            return result;
        }
    }
}
