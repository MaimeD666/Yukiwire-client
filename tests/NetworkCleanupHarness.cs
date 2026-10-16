using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Yukiwire;
namespace Yukiwire { public static class NetworkBroker {
 internal static void CleanEnvironment(ProcessStartInfo info) { throw new Exception("A missing adapter must not launch a command"); }
} }
class CleanupHarness {
 static void Check(bool value) { if(!value)throw new Exception("IP Helper ABI/ownership regression"); }
 static int Main() {
  Check(Marshal.SizeOf(typeof(NetworkCleanup.Address)) == 28);
  Check(Marshal.SizeOf(typeof(NetworkCleanup.Prefix)) == 32);
  Check(Marshal.SizeOf(typeof(NetworkCleanup.Route)) == 104);
  Check(Marshal.OffsetOf(typeof(NetworkCleanup.Route),"metric").ToInt32() == 84);
  Check(Marshal.SizeOf(typeof(NetworkCleanup.Unicast)) == 80);
  Check(Marshal.OffsetOf(typeof(NetworkCleanup.Unicast),"index").ToInt32() == 40);
  Check(Marshal.OffsetOf(typeof(NetworkCleanup.Unicast),"prefix").ToInt32() == 60);
  string token=Guid.NewGuid().ToString("N").Substring(0,12);
  Check(NetworkCleanup.Remove("Yukiwire-"+token,"Yukiwire "+token));
  try {NetworkCleanup.Remove("Ethernet","arbitrary");return 2;}catch(InvalidOperationException){}
  Console.WriteLine("IP Helper layouts and missing/foreign adapter guards passed; no network changes.");return 0;
 }
}
