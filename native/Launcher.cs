using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

class Launcher {
 [STAThread] static int Main() {
  string root = AppDomain.CurrentDomain.BaseDirectory;
  string shell = Path.Combine(root,"runtime","Yukiwire.exe");
  string python = Path.Combine(root,"runtime","embedded-python","python.exe");
  if (!File.Exists(python)) python = Environment.GetEnvironmentVariable("YUKIWIRE_PYTHON");
  if (!File.Exists(shell) || String.IsNullOrEmpty(python) || !File.Exists(python)) {
   MessageBox.Show("Для первого запуска из исходников откройте run.cmd.\nГотовая переносимая версия находится в папке dist.","Yukiwire"); return 1;
  }
  var start = new ProcessStartInfo(shell) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = root };
  start.EnvironmentVariables["YUKIWIRE_ROOT"] = root; start.EnvironmentVariables["YUKIWIRE_PYTHON"] = python;
  try { Process.Start(start); return 0; }
  catch (Exception) { MessageBox.Show("Не удалось запустить Yukiwire. Повторите сборку через run.cmd.","Yukiwire"); return 1; }
 }
}
