// SPDX-License-Identifier: Apache-2.0
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace RdpWrapMaintenance {
    public static class Trust {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct FileInfo { public uint Size; [MarshalAs(UnmanagedType.LPWStr)] public string Path; public IntPtr Handle, Subject; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct CatalogInfo { public uint Size, Version; [MarshalAs(UnmanagedType.LPWStr)] public string Catalog, Tag, Member; public IntPtr Handle, Hash; public uint HashSize; public IntPtr Context, Admin; }
        [StructLayout(LayoutKind.Sequential)] struct TrustData { public uint Size; public IntPtr Policy, Sip; public uint Ui, Revocation, Choice; public IntPtr Subject; public uint Action; public IntPtr State, Url; public uint Flags, UiContext; public IntPtr SignatureSettings; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct CatalogPath { public uint Size; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Path; }
        [DllImport("wintrust.dll", ExactSpelling = true)] static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string algorithm, IntPtr policy, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, IntPtr file, ref uint size, byte[] hash, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)] static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint size, uint flags, ref IntPtr previous);
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogPath info, uint flags);
        [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, uint flags);
        [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);
        static bool Verify<T>(T subject, uint choice) {
            IntPtr pointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
            var data = new TrustData { Size = (uint)Marshal.SizeOf(typeof(TrustData)), Ui = 2, Choice = choice, Subject = pointer, Action = 1, Flags = 0x1000 };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            try { Marshal.StructureToPtr(subject, pointer, false); return WinVerifyTrust(IntPtr.Zero, ref action, ref data) == 0; }
            finally { data.Action = 2; WinVerifyTrust(IntPtr.Zero, ref action, ref data); Marshal.DestroyStructure(pointer, typeof(T)); Marshal.FreeHGlobal(pointer); }
        }
        public static bool Valid(string path) {
            if (Verify(new FileInfo { Size = (uint)Marshal.SizeOf(typeof(FileInfo)), Path = path }, 1)) return true;
            // Windows system DLLs are normally catalog-signed rather than carrying
            // an embedded signature. Verify the file's membership, not just the
            // certificate of an unrelated catalog file.
            foreach (string algorithm in new[] { "SHA256", "SHA1" }) {
                IntPtr admin; if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) continue;
                IntPtr catalog = IntPtr.Zero, hashPointer = IntPtr.Zero;
                try {
                    using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
                        uint length = 0; CryptCATAdminCalcHashFromFileHandle2(admin, file.SafeFileHandle.DangerousGetHandle(), ref length, null, 0);
                        if (length == 0 || length > 128) continue;
                        var hash = new byte[length]; if (!CryptCATAdminCalcHashFromFileHandle2(admin, file.SafeFileHandle.DangerousGetHandle(), ref length, hash, 0)) continue;
                        IntPtr previous = IntPtr.Zero; catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, length, 0, ref previous); if (catalog == IntPtr.Zero) continue;
                        var info = new CatalogPath { Size = (uint)Marshal.SizeOf(typeof(CatalogPath)) }; if (!CryptCATCatalogInfoFromContext(catalog, ref info, 0)) continue;
                        hashPointer = Marshal.AllocHGlobal((int)length); Marshal.Copy(hash, 0, hashPointer, (int)length);
                        var subject = new CatalogInfo { Size = (uint)Marshal.SizeOf(typeof(CatalogInfo)), Catalog = info.Path, Tag = BitConverter.ToString(hash).Replace("-", ""), Member = path, Handle = file.SafeFileHandle.DangerousGetHandle(), Hash = hashPointer, HashSize = length, Admin = admin };
                        if (Verify(subject, 2)) return true;
                    }
                } finally { if (hashPointer != IntPtr.Zero) Marshal.FreeHGlobal(hashPointer); if (catalog != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, catalog, 0); CryptCATAdminReleaseContext(admin, 0); }
            }
            return false;
        }
    }
}
