using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Yukiwire {
 // Elevated mode contains no UI/browser. The pipe is created by the normal-user host
 // with a current-user ACL; both endpoints additionally bind the peer process identity.
 public static class NetworkWorker {
  [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetNamedPipeServerProcessId(IntPtr pipe,out uint pid);
  [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetNamedPipeClientProcessId(IntPtr pipe,out uint pid);
  public static int Run(string[] args) {
   bool test = args.Length == 6 && args[5] == "--test-session";
   if (args.Length != 5 && !test || !Regex.IsMatch(args[1],@"^Yukiwire\.[a-f0-9]{32}$")) return 2;
   int parentId; long parentTime;
   if (!Int32.TryParse(args[2],out parentId) || !Int64.TryParse(args[3],out parentTime)) return 2;
   string root = File.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"portable.json")) ? AppDomain.CurrentDomain.BaseDirectory : Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,".."));
   string bundled = Path.Combine(root,"python","python.exe");
   string python = File.Exists(bundled) ? bundled : args[4];
   if (!File.Exists(python)) return 2;
   try {
    using (var parent = Process.GetProcessById(parentId)) {
     if (parent.StartTime.ToUniversalTime().ToFileTimeUtc() != parentTime || parent.HasExited) return 3;
     using (var pipe = new NamedPipeClientStream(".",args[1],PipeDirection.InOut,PipeOptions.Asynchronous)) {
      pipe.Connect(15000);
      uint serverId;
      if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(),out serverId) || serverId != parentId) return 3;
      string command = "-B -u \"" + Path.Combine(root,"scripts","worker.py") + "\" --worker yukiwire.backend";
      using (var service = new Process { StartInfo = new ProcessStartInfo(python,command) { WorkingDirectory = root, UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 } }) {
       service.StartInfo.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8";
       service.StartInfo.EnvironmentVariables["PYTHON_DISABLE_REMOTE_DEBUG"] = "1";
       service.StartInfo.EnvironmentVariables["YUKIWIRE_TEST_SESSION"] = test ? "1" : "0";
       service.Start(); service.ErrorDataReceived += delegate { }; service.BeginErrorReadLine();
       // Holding this Process object binds the parent handle, avoiding PID reuse.
       var parentWatch = new Thread(delegate() { try { parent.WaitForExit(); service.StandardInput.Close(); pipe.Dispose(); } catch (Exception) { } });
       parentWatch.IsBackground = true; parentWatch.Start();
       var writer = new StreamWriter(pipe,new UTF8Encoding(false),4096,true) { AutoFlush = true };
       var reader = new StreamReader(pipe,Encoding.UTF8,false,4096,true);
       var output = new Thread(delegate() {
        try { string line; while ((line = service.StandardOutput.ReadLine()) != null) writer.WriteLine(line); }
        catch (Exception) { }
        finally { try { pipe.Dispose(); } catch (Exception) { } }
       }); output.IsBackground = true; output.Start();
       try {
        string line;
        while ((line = reader.ReadLine()) != null) {
         if (line.Length > 4 * 1024 * 1024) break;
         service.StandardInput.WriteLine(line); service.StandardInput.Flush();
        }
       } catch (Exception) { }
       finally {
        try { service.StandardInput.Close(); if (!service.WaitForExit(4000)) { service.Kill(); service.WaitForExit(1500); } } catch (Exception) { }
       } return 0;
      }
     }
    }
   } catch (Exception) { return 4; }
  }
 }
}
