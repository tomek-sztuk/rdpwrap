// SPDX-License-Identifier: Apache-2.0
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;

namespace RdpWrapMaintenance {
    public static class LsaSessions {
        [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
        [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, Maximum; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] struct Prefix { public uint Size; public Luid Id; public UnicodeString User, Domain, Package; public uint Type, Session; }
        [DllImport("secur32.dll")] static extern uint LsaEnumerateLogonSessions(out uint count, out IntPtr sessions);
        [DllImport("secur32.dll")] static extern uint LsaGetLogonSessionData(ref Luid id, out IntPtr data);
        [DllImport("secur32.dll")] static extern uint LsaFreeReturnBuffer(IntPtr buffer);
        [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
        [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();
        static string Text(UnicodeString text) { if ((text.Length & 1) != 0 || text.Length > text.Maximum || (text.Length != 0 && text.Buffer == IntPtr.Zero)) throw new MaintenanceException("Invalid LSA session text"); return text.Length == 0 ? "" : Marshal.PtrToStringUni(text.Buffer, text.Length / 2); }
        public static List<Session> Read() {
            uint count; IntPtr list; uint status = LsaEnumerateLogonSessions(out count, out list);
            if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status));
            var sessions = new Dictionary<int, Session>(); uint console = WTSGetActiveConsoleSessionId();
            try {
                if (count > 100000) throw new MaintenanceException("LSA session count exceeds bounds");
                for (int i = 0; i < count; i++) {
                    var id = (Luid)Marshal.PtrToStructure(IntPtr.Add(list, i * Marshal.SizeOf(typeof(Luid))), typeof(Luid)); IntPtr data;
                    // LocalSystem is not an interactive logon and Windows returns
                    // zero session data for its well-known 0:3e7 logon ID.
                    if (id.Low == 0x3e7 && id.High == 0) continue;
                    status = LsaGetLogonSessionData(ref id, out data);
                    if (status != 0) throw new Win32Exception((int)LsaNtStatusToWinError(status));
                    if (data == IntPtr.Zero) throw new MaintenanceException("LSA session data missing");
                    try {
                        var prefix = (Prefix)Marshal.PtrToStructure(data, typeof(Prefix));
                        if (prefix.Size < Marshal.SizeOf(typeof(Prefix))) throw new MaintenanceException("Incomplete LSA session data");
                        // Interactive, unlock and cached interactive logons. The
                        // remote logon types remain present for disconnected users.
                        if (!new uint[] { 2, 7, 10, 11, 12, 13 }.Contains(prefix.Type)) continue;
                        string user = Text(prefix.User), domain = Text(prefix.Domain);
                        bool remote = prefix.Type == 10 || prefix.Type == 12;
                        if (prefix.Session == 0 && !remote) continue;
                        int session = checked((int)prefix.Session); Session old;
                        if (sessions.TryGetValue(session, out old) && old.Protocol == 2) continue;
                        sessions[session] = new Session { Id = session, Protocol = remote ? 2 : 0, User = domain.Length == 0 ? user : domain + "\\" + user, Station = prefix.Session == console ? "Console" : "LSA-non-console", State = "LogonPresent" };
                    } finally { LsaFreeReturnBuffer(data); }
                }
            } finally { LsaFreeReturnBuffer(list); }
            return sessions.Values.ToList();
        }
    }
}
