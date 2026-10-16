using System;
using System.Diagnostics;
using System.Threading;
using Yukiwire;

// Test-only watchdog on a disposable VM. It knows only this test's WFP keys.
public static class NetworkRescue {
 public static int Main(string[] args) {
  if (args.Length != 4) return 2;
  using (var owner = Process.GetProcessById(Int32.Parse(args[0]))) {
   if (owner.StartTime.ToUniversalTime().ToFileTimeUtc() != Int64.Parse(args[1])) return 3;
   if (!owner.WaitForExit(300000)) { owner.Kill(); owner.WaitForExit(); }
  }
  // EOF cleanup may remove the TUN permit while we recover. Repeat until it settles.
  for (int i = 0; i < 30; i++) {
   try { using (var filter = new NetworkFilter(args[2],args[3])) filter.Remove(); }
   catch (Exception) {}
   Thread.Sleep(1000);
  }
  return 0;
 }
}
