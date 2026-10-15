using System;
using System.Runtime.InteropServices;
using Yukiwire;
class NetworkFilterHarness {
 static void Check(bool value) { if (!value) throw new Exception("Invalid Windows x64 WFP ABI"); }
 static int Main() {
  // These offsets are the published x64 Windows SDK structures, independent of
  // the implementation. This executable never opens WFP or changes any filter.
  Check(IntPtr.Size == 8);
  Check(Marshal.SizeOf(typeof(NetworkFilter.Filter)) == 200);
  Check(Marshal.SizeOf(typeof(NetworkFilter.Condition)) == 40);
  Check(Marshal.SizeOf(typeof(NetworkFilter.Sublayer)) == 72);
  Check(Marshal.OffsetOf(typeof(NetworkFilter.Filter),"conditions").ToInt32() == 120);
  Check(Marshal.OffsetOf(typeof(NetworkFilter.Filter),"action").ToInt32() == 128);
  Check(Marshal.OffsetOf(typeof(NetworkFilter.Filter),"context").ToInt32() == 152);
  Check(Marshal.OffsetOf(typeof(NetworkFilter.Filter),"id").ToInt32() == 176);
  Console.WriteLine("Windows x64 WFP ABI verified; no network filters changed.");
  return 0;
 }
}
