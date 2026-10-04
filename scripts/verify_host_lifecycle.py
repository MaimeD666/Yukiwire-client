"""Exercise the actual WPF host with fake children; no UI, browser or network changes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from build_native import build

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;
class LifecycleCheck {
 const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
 static Window Shell(Type type) {
  return (Window)Activator.CreateInstance(type,new object[] {true,false,null,false,false,false,false});
 }
 [STAThread] static void Main(string[] args) {
  var type=Assembly.LoadFrom(args[0]).GetType("Yukiwire.WebShell");
  foreach(string mode in new[] {"graceful","hung"}) {
   var shell=Shell(type);
   var marker=Path.Combine(args[2],mode+".txt");
   using(var child=new Process {StartInfo=new ProcessStartInfo(args[1],"\""+Path.Combine(args[2],"service.py")+"\" "+mode+" \""+marker+"\"") {
    UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true
   }}) {
    child.Start();
    if(child.StandardOutput.ReadLine()!="READY") throw new Exception("Fixture failed to start");
    type.GetField("backend",Private).SetValue(shell,child);
    var watch=Stopwatch.StartNew();
    try {
     type.GetMethod("PrepareShutdown").Invoke(shell,null);
     type.GetMethod("PrepareShutdown").Invoke(shell,null);
     if(!child.HasExited || watch.ElapsedMilliseconds>6500) throw new Exception("Unbounded or incomplete host shutdown");
     if(mode=="graceful" && File.ReadAllText(marker).Trim()!="quit") throw new Exception("No graceful quit command");
     Console.WriteLine(mode+" backend: stopped, repeated shutdown harmless ("+watch.ElapsedMilliseconds+" ms)");
    } finally {if(!child.HasExited) child.Kill(); shell.Close();}
   }
  }
  var browserShell=Shell(type);
  try {
   var launch=(Task)type.GetMethod("OpenProxyBrowser",Private).Invoke(browserShell,null);
   if(!launch.Wait(8000)) throw new Exception("Browser broker timed out");
   var lines=File.ReadAllLines(Path.Combine(args[2],"browser-token.txt"));
   bool admin=new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
   if(lines[0]!=Process.GetCurrentProcess().Id.ToString() || lines[1]!=(admin?"1":"0"))
    throw new Exception("Browser helper did not inherit the host process/token");
   Console.WriteLine("Browser broker: helper is a child of the UI host with its privilege level; no browser launched");
  } finally {browserShell.Close();}
 }
}
'''


def main():
    executable = build()
    # A venv's Windows redirector adds an intermediate process; use the real interpreter.
    python = str(Path(sys.base_prefix) / 'python.exe')
    framework = Path(os.environ.get('WINDIR', r'C:\Windows')) / 'Microsoft.NET/Framework64/v4.0.30319'
    source, harness = ROOT / 'build/host-lifecycle.cs', ROOT / 'build/host-lifecycle.exe'
    source.write_text(HARNESS, encoding='utf-8')
    references = [framework / 'WPF' / name for name in ('PresentationFramework.dll', 'PresentationCore.dll', 'WindowsBase.dll')]
    references += [framework / name for name in ('System.Drawing.dll', 'System.Windows.Forms.dll', 'System.Xaml.dll')]
    subprocess.run([str(framework / 'csc.exe'), '/nologo', '/target:exe', '/platform:x64', '/out:' + str(harness),
                    *('/reference:' + str(path) for path in references), str(source)], check=True)
    with tempfile.TemporaryDirectory(prefix='host-lifecycle-', dir=ROOT / 'build') as temporary:
        fixture = Path(temporary)
        (fixture / 'scripts').mkdir()
        (fixture / 'service.py').write_text(
            "import json,sys,time\nfrom pathlib import Path\nprint('READY',flush=True)\n"
            "if sys.argv[1]=='hung': time.sleep(30)\n"
            "else: Path(sys.argv[2]).write_text(json.loads(sys.stdin.readline())['action'])\n", encoding='utf-8')
        (fixture / 'scripts/worker.py').write_text(
            "import ctypes,json,os\nfrom pathlib import Path\n"
            "Path('browser-token.txt').write_text(str(os.getppid())+'\\n'+str(int(bool(ctypes.windll.shell32.IsUserAnAdmin()))))\n"
            "print(json.dumps({'event':'browser_opened','browser':'fixture'}),flush=True)\n", encoding='utf-8')
        result = subprocess.run([str(harness), str(executable), python, temporary], timeout=20,
                                env=dict(os.environ, YUKIWIRE_ROOT=temporary, YUKIWIRE_PYTHON=python),
                                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        print(result.stdout)
        if result.returncode:
            print(result.stderr)
        result.check_returncode()


if __name__ == '__main__':
    main()
