"""Query the actual native window hook on each monitor without showing a window or starting a backend."""
import os
from pathlib import Path
import subprocess

from build_native import build

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
using System;
using System.IO;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Forms;
class BoundsCheck {
 [StructLayout(LayoutKind.Sequential)] struct Point { public int X, Y; }
 [StructLayout(LayoutKind.Sequential)] struct Bounds { public Point Reserved, Size, Position, Min, Max; }
 [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr hwnd, uint message, IntPtr wparam, IntPtr lparam);
 [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int width, int height, uint flags);
 [STAThread] static int Main(string[] args) {
  var assembly = Assembly.LoadFrom(args[0]);
  var shell = (Window)Activator.CreateInstance(assembly.GetType("Yukiwire.WebShell"),new object[] {true,false,null,false,false,false,false});
  IntPtr memory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Bounds)));
  var report = new List<string>();
  try {
   var handle = new WindowInteropHelper(shell).EnsureHandle();
   if (Screen.AllScreens.Length == 0) throw new Exception("No monitors available for verification");
   foreach (var screen in Screen.AllScreens) {
    // No SWP_SHOWWINDOW: this test never activates or displays the window.
    if (!SetWindowPos(handle,IntPtr.Zero,screen.Bounds.Left+20,screen.Bounds.Top+20,400,300,0x0014)) throw new Exception("SetWindowPos failed");
    Marshal.StructureToPtr(new Bounds(),memory,false);
    SendMessage(handle,0x0024,IntPtr.Zero,memory);
    var bounds = (Bounds)Marshal.PtrToStructure(memory,typeof(Bounds));
    var work = screen.WorkingArea;
    if (bounds.Size.X != work.Width || bounds.Size.Y != work.Height ||
        bounds.Position.X != work.Left-screen.Bounds.Left || bounds.Position.Y != work.Top-screen.Bounds.Top)
     throw new Exception("Maximized client does not match the monitor work area: " + screen.DeviceName);
    if (bounds.Min.X <= 0 || bounds.Min.Y <= 0 || bounds.Min.X > work.Width || bounds.Min.Y > work.Height)
     throw new Exception("Invalid minimum tracking size");
    report.Add(screen.DeviceName + ": work area " + work.Width + "x" + work.Height + ", maximize bounds passed");
   }
  } finally { Marshal.FreeHGlobal(memory); shell.Close(); }
  File.WriteAllLines(args[1],report);
  return 0;
 }
}
'''


def main():
    executable = build()
    framework = Path(os.environ.get('WINDIR', r'C:\Windows')) / 'Microsoft.NET/Framework64/v4.0.30319'
    source = ROOT / 'build/window-bounds-check.cs'
    harness = ROOT / 'build/window-bounds-check.exe'
    source.write_text(HARNESS, encoding='utf-8')
    references = [framework / 'WPF' / name for name in ('PresentationFramework.dll', 'PresentationCore.dll', 'WindowsBase.dll')]
    references += [framework / name for name in ('System.Drawing.dll', 'System.Windows.Forms.dll', 'System.Xaml.dll')]
    subprocess.run([str(framework / 'csc.exe'), '/nologo', '/target:exe', '/platform:x64',
                    '/out:' + str(harness), '/win32manifest:' + str(ROOT / 'native/app.manifest'),
                    *('/reference:' + str(path) for path in references), str(source)], check=True)
    report = ROOT / 'runtime/window-bounds-report.txt'
    subprocess.run([str(harness), str(executable), str(report)], check=True, timeout=20,
                   env=dict(os.environ, YUKIWIRE_ROOT=str(ROOT)), creationflags=subprocess.CREATE_NO_WINDOW)
    print(report.read_text(encoding='utf-8'))


if __name__ == '__main__':
    main()
