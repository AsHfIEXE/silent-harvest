using System;
using System.Runtime.InteropServices;
using System.Text;

public static class GcmProbe
{
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    static extern int BCryptOpenAlgorithmProvider(out IntPtr h, string alg, string impl, uint f);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    static extern int BCryptSetProperty(IntPtr o, string p, byte[] v, int n, int f);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    static extern int BCryptGetProperty(IntPtr o, string p, byte[] v, int n, out int r, int f);
    [DllImport("bcrypt.dll")]
    static extern int BCryptGenerateSymmetricKey(IntPtr a, out IntPtr k, IntPtr ko, int cko,
                                                 byte[] secret, int cb, int f);
    [DllImport("bcrypt.dll")]
    static extern int BCryptDestroyKey(IntPtr k);
    [DllImport("bcrypt.dll")]
    static extern int BCryptCloseAlgorithmProvider(IntPtr a, uint f);

    [StructLayout(LayoutKind.Sequential)]
    public struct AUTH
    {
        public int cbSize; public int dwInfoVersion;
        public IntPtr pbNonce; public int cbNonce;
        public IntPtr pbAuthData; public int cbAuthData;
        public IntPtr pbTag; public int cbTag;
        public IntPtr pbMacContext; public int cbMacContext;
        public int cbAAD; public int cbData; public int dwFlags;
    }

    [DllImport("bcrypt.dll")]
    static extern int BCryptEncrypt(IntPtr k, byte[] inb, int cinb, ref AUTH ai,
                                    byte[] iv, int civ, byte[] outb, int coutb,
                                    out int res, int f);

    [DllImport("bcrypt.dll", EntryPoint = "BCryptEncrypt")]
    static extern int BCryptEncryptNI(IntPtr k, byte[] inb, int cinb, IntPtr ai,
                                      byte[] iv, int civ, byte[] outb, int coutb,
                                      out int res, int f);

    static string Hex(int st) { return "0x" + ((uint)(int)st).ToString("X8"); }

    static int Run(string label, bool ivAsNonce, bool withAad, int flags, bool bigOut, int tagLen)
    {
        return Run(label, ivAsNonce, withAad, flags, bigOut, tagLen, 16);
    }

    static int Run(string label, bool ivAsNonce, bool withAad, int flags, bool bigOut, int tagLen, int extraOut)
    {
        IntPtr hAlg, hKey, keyObj;
        int st = BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
        if (st != 0) { Console.WriteLine(label + ": open " + Hex(st)); return -1; }
        byte[] mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
        st = BCryptSetProperty(hAlg, "ChainingMode", mode, mode.Length, 0);
        if (st != 0) { Console.WriteLine(label + ": mode " + Hex(st)); return -1; }
        byte[] objLen = new byte[4]; int got;
        BCryptGetProperty(hAlg, "ObjectLength", objLen, 4, out got, 0);
        keyObj = Marshal.AllocHGlobal(BitConverter.ToInt32(objLen, 0));
        byte[] key = new byte[32]; for (int i = 0; i < 32; i++) key[i] = (byte)i;
        st = BCryptGenerateSymmetricKey(hAlg, out hKey, keyObj, BitConverter.ToInt32(objLen, 0), key, 32, 0);
        if (st != 0) { Console.WriteLine(label + ": genkey " + Hex(st)); return -1; }

        byte[] nonce = new byte[12]; for (int i = 0; i < 12; i++) nonce[i] = (byte)(0xA0 + i);
        byte[] aad = withAad ? new byte[] { 1, 2, 3, 4, 5, 6 } : null;
        byte[] pt = Encoding.ASCII.GetBytes("attack at dawn!!");
        byte[] tag = new byte[Math.Max(tagLen, 16)];

        GCHandle gn = GCHandle.Alloc(nonce, GCHandleType.Pinned);
        GCHandle gt = GCHandle.Alloc(tag, GCHandleType.Pinned);
        GCHandle ga = aad != null ? GCHandle.Alloc(aad, GCHandleType.Pinned) : new GCHandle();
        AUTH ai = new AUTH();
        ai.cbSize = Marshal.SizeOf(typeof(AUTH));
        ai.dwInfoVersion = 1;
        Console.WriteLine(label + ": sizeof(AUTH)=" + ai.cbSize);
        try
        {
            ai.pbNonce = gn.AddrOfPinnedObject(); ai.cbNonce = 12;
            ai.pbTag = gt.AddrOfPinnedObject(); ai.cbTag = tagLen;
            if (aad != null) { ai.pbAuthData = ga.AddrOfPinnedObject(); ai.cbAuthData = aad.Length; }

            byte[] ivArg = ivAsNonce ? nonce : null;
            byte[] ct = new byte[pt.Length + (bigOut ? 16 : 0) + extraOut];
            int res;
            st = BCryptEncrypt(hKey, pt, pt.Length, ref ai, ivArg, ivAsNonce ? 12 : 0,
                               ct, ct.Length, out res, flags);
            Console.WriteLine(label + ": encrypt " + Hex(st) +
                              (st == 0 ? " res=" + res + " ct=" + BitConverter.ToString(ct, 0, res).Replace("-", "") +
                               " tag=" + BitConverter.ToString(tag).Replace("-", "") : ""));
            return st;
        }
        finally
        {
            if (gn.IsAllocated) gn.Free();
            if (gt.IsAllocated) gt.Free();
            if (ga.IsAllocated) ga.Free();
            BCryptDestroyKey(hKey);
            Marshal.FreeHGlobal(keyObj);
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    static void Main()
    {
        Run("v1 authinfo-nonce / aad", false, true, 0, false, 16);
        Run("v2 pbIV-as-nonce / aad", true, true, 0, false, 16);
        Run("v3 authinfo-nonce / no aad", false, false, 0, false, 16);
        Run("v4 pbIV-as-nonce / no aad", true, false, 0, false, 16);
        Run("a1 f0 out=in", false, false, 0, false, 16);
        Run("a2 f1 out=in", false, false, 1, false, 16);
        Run("a3 f1 out=in+16", false, false, 1, true, 16);
        Run("a4 f0 out=in+16", false, false, 0, true, 16);
        Run("a5 f0 out=in+64", false, false, 0, false, 16, 64);
        Run("a6 f1 out=in+64", false, false, 1, false, 16, 64);
        HandBuilt();
        CbcControl();
    }

    static void HandBuilt()
    {
        // same as v1 but the auth-info struct is hand-packed into raw memory
        IntPtr hAlg, hKey, keyObj;
        int st = BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
        byte[] mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
        BCryptSetProperty(hAlg, "ChainingMode", mode, mode.Length, 0);
        byte[] objLen = new byte[4]; int got;
        BCryptGetProperty(hAlg, "ObjectLength", objLen, 4, out got, 0);
        keyObj = Marshal.AllocHGlobal(BitConverter.ToInt32(objLen, 0));
        byte[] key = new byte[32]; for (int i = 0; i < 32; i++) key[i] = (byte)i;
        BCryptGenerateSymmetricKey(hAlg, out hKey, keyObj, BitConverter.ToInt32(objLen, 0), key, 32, 0);

        byte[] nonce = new byte[12]; for (int i = 0; i < 12; i++) nonce[i] = (byte)(0xA0 + i);
        byte[] aad = new byte[] { 1, 2, 3, 4, 5, 6 };
        byte[] pt = Encoding.ASCII.GetBytes("attack at dawn!!");
        byte[] tag = new byte[16];

        GCHandle gn = GCHandle.Alloc(nonce, GCHandleType.Pinned);
        GCHandle ga = GCHandle.Alloc(aad, GCHandleType.Pinned);
        GCHandle gt = GCHandle.Alloc(tag, GCHandleType.Pinned);
        IntPtr info = Marshal.AllocHGlobal(80);
        for (int i = 0; i < 80; i++) Marshal.WriteByte(info, i, 0);
        try
        {
            Marshal.WriteInt32(info, 0, 80);                        // cbSize
            Marshal.WriteInt32(info, 4, 1);                         // dwInfoVersion
            Marshal.WriteIntPtr(info, 8, gn.AddrOfPinnedObject());  // pbNonce
            Marshal.WriteInt32(info, 16, 12);                       // cbNonce
            Marshal.WriteIntPtr(info, 24, ga.AddrOfPinnedObject()); // pbAuthData
            Marshal.WriteInt32(info, 32, aad.Length);               // cbAuthData
            Marshal.WriteIntPtr(info, 40, gt.AddrOfPinnedObject()); // pbTag
            Marshal.WriteInt32(info, 48, 16);                       // cbTag

            byte[] ct = new byte[pt.Length];
            int res;
            st = BCryptEncryptNI(hKey, pt, pt.Length, info, null, 0, ct, ct.Length, out res, 0);
            Console.WriteLine("hand-built authinfo: " + Hex(st) +
                (st == 0 ? " ct=" + BitConverter.ToString(ct, 0, res).Replace("-", "") +
                 " tag=" + BitConverter.ToString(tag).Replace("-", "") : ""));
        }
        finally
        {
            Marshal.FreeHGlobal(info);
            gn.Free(); ga.Free(); gt.Free();
            BCryptDestroyKey(hKey); Marshal.FreeHGlobal(keyObj); BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    static void CbcControl()
    {
        IntPtr hAlg, hKey, keyObj;
        int st = BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
        byte[] mode = Encoding.Unicode.GetBytes("ChainingModeCBC\0");
        st = BCryptSetProperty(hAlg, "ChainingMode", mode, mode.Length, 0);
        byte[] objLen = new byte[4]; int got;
        BCryptGetProperty(hAlg, "ObjectLength", objLen, 4, out got, 0);
        keyObj = Marshal.AllocHGlobal(BitConverter.ToInt32(objLen, 0));
        byte[] key = new byte[32]; for (int i = 0; i < 32; i++) key[i] = (byte)i;
        st = BCryptGenerateSymmetricKey(hAlg, out hKey, keyObj, BitConverter.ToInt32(objLen, 0), key, 32, 0);
        byte[] pt = Encoding.ASCII.GetBytes("attack at dawn!!");
        byte[] iv = new byte[16];
        byte[] ct = new byte[pt.Length + 16];
        int res;
        st = BCryptEncryptNI(hKey, pt, pt.Length, dummyInfo, iv, 16, ct, ct.Length, out res, 1);
        Console.WriteLine("cbc control: " + Hex(st) + (st == 0 ? " res=" + res : ""));
        BCryptDestroyKey(hKey); Marshal.FreeHGlobal(keyObj); BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    static IntPtr dummyInfo = IntPtr.Zero;
}
