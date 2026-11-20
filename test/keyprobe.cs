using System;
using System.Runtime.InteropServices;
using System.Text;

public static class KeyProbe
{
    [DllImport("ntdll.dll")]
    static extern int NtOpenKeyEx(out IntPtr h, uint access, ref OA oa, uint opts);
    [DllImport("ntdll.dll")]
    static extern int RtlNtStatusToDosError(int st);

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    public struct OA
    {
        public int Length; public IntPtr Root; public IntPtr Name; public uint Attr;
        public IntPtr Sd; public IntPtr Qos;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegQueryValueExW(IntPtr h, string name, IntPtr r, out int type,
        byte[] data, ref int len);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegQueryInfoKeyW(IntPtr h, StringBuilder cls, ref int cchCls, IntPtr reserved,
        IntPtr pcSubKeys, IntPtr pcbMaxSubKeyLen, IntPtr pcbMaxClassLen,
        IntPtr pcValues, IntPtr pcbMaxValueNameLen, IntPtr pcbMaxValueLen,
        IntPtr pcbSecDesc, IntPtr lpftLastWriteTime);

    static void Probe(string path)
    {
        byte[] pb = Encoding.Unicode.GetBytes(path);
        IntPtr buf = Marshal.AllocHGlobal(pb.Length + 2);
        Marshal.Copy(pb, 0, buf, pb.Length);
        Marshal.WriteInt16(buf, pb.Length, 0);
        UNICODE_STRING us = new UNICODE_STRING { Length = (ushort)pb.Length, MaximumLength = (ushort)(pb.Length + 2), Buffer = buf };
        IntPtr usp = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(us, usp, false);
        OA oa = new OA { Length = Marshal.SizeOf(typeof(OA)), Name = usp, Attr = 0x40 };
        IntPtr h;
        int st = NtOpenKeyEx(out h, 0x20019, ref oa, 0);
        Console.WriteLine(path + " open: 0x" + st.ToString("X8"));
        if (st == 0)
        {
            {
                StringBuilder cls = new StringBuilder(256);
                int cch = 256;
                int rc = RegQueryInfoKeyW(h, cls, ref cch, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                Console.WriteLine("  class rc=" + rc + " cch=" + cch +
                    " class='" + cls.ToString() + "' hex=" +
                    BitConverter.ToString(Encoding.Unicode.GetBytes(cls.ToString())));
            }
            foreach (string vn in new string[] { "Data", "" })
            {
                int type; int len = 0;
                int rc = RegQueryValueExW(h, vn, IntPtr.Zero, out type, null, ref len);
                if (rc == 0)
                {
                    byte[] data = new byte[len];
                    RegQueryValueExW(h, vn, IntPtr.Zero, out type, data, ref len);
                    Console.WriteLine("  value '" + (vn == "" ? "<default>" : vn) + "' type=" + type +
                        " len=" + len + " hex=" + BitConverter.ToString(data));
                }
                else Console.WriteLine("  value '" + (vn == "" ? "<default>" : vn) + "' rc=" + rc);
            }
        }
        Marshal.FreeHGlobal(buf); Marshal.FreeHGlobal(usp);
    }

    static void Main()
    {
        Probe(@"\Registry\Machine\SYSTEM\ControlSet001\Control\Lsa\JD");
        Probe(@"\Registry\Machine\SYSTEM\ControlSet001\Control\Lsa\Skew1");
        Probe(@"\Registry\Machine\SYSTEM\ControlSet001\Control\Lsa\Data");
    }
}
