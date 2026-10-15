using System;
using Yukiwire;
public static class NetworkPolicyHarness {
 public static int Main() {
  try { Console.Write(NetworkPolicy.Validate(Console.In.ReadToEnd(),"Yukiwire-0123456789ab","Yukiwire 0123456789ab",false)); return 0; }
  catch (Exception) { return 2; }
 }
}
