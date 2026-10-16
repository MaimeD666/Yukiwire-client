using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace Yukiwire {
 // x64 IP Helper layouts. Deletion uses the exact rows inspected below.
 public static class NetworkCleanup {
  [StructLayout(LayoutKind.Explicit,Size=28)] public struct Address {
   [FieldOffset(0)] public ushort family;
   [FieldOffset(4)] public uint ipv4;
   [FieldOffset(8)] public uint a;
   [FieldOffset(12)] public uint b;
   [FieldOffset(16)] public uint c;
   [FieldOffset(20)] public uint d;
  }
  [StructLayout(LayoutKind.Sequential)] public struct Prefix { public Address address; public byte length; }
  [StructLayout(LayoutKind.Sequential)] public struct Route {
   public ulong luid; public uint index; public Prefix prefix; public Address hop; public byte site;
   public uint valid,preferred,metric,protocol; public byte loopback,auto,publish,immortal; public uint age,origin;
  }
  [StructLayout(LayoutKind.Sequential)] public struct Unicast {
   public Address address; public ulong luid; public uint index,prefixOrigin,suffixOrigin,valid,preferred;
   public byte prefix,skip; public uint dad,scope; public long created;
  }
  [DllImport("iphlpapi.dll")] static extern uint GetIpForwardTable2(ushort family,out IntPtr table);
  [DllImport("iphlpapi.dll")] static extern uint GetUnicastIpAddressTable(ushort family,out IntPtr table);
  [DllImport("iphlpapi.dll")] static extern uint DeleteIpForwardEntry2(IntPtr row);
  [DllImport("iphlpapi.dll")] static extern uint DeleteUnicastIpAddressEntry(IntPtr row);
  [DllImport("iphlpapi.dll")] static extern void FreeMibTable(IntPtr table);
  public static int Stage { get; private set; }
  public static int ExitCode { get; private set; }
  static bool Zero(Address address) {
   return address.family == 2 ? address.ipv4 == 0 : address.family == 23 && (address.a | address.b | address.c | address.d) == 0;
  }
  static bool Capture(Prefix prefix) {
   Address a=prefix.address;
   return prefix.length == 1 && (a.family == 2 && (a.ipv4 == 0 || a.ipv4 == 128) ||
    a.family == 23 && (a.a == 0 || a.a == 128) && (a.b | a.c | a.d) == 0);
  }
  static bool OwnAddress(Unicast row) {
   Address a=row.address;
   // Network bytes: 172.29.250.1 and fd72:756b:6977::1; read on Windows x64.
   return a.family == 2 && row.prefix == 30 && a.ipv4 == 0x01fa1dac ||
    a.family == 23 && row.prefix == 126 && a.a == 0x6b7572fd && a.b == 0x00007769 && a.c == 0 && a.d == 0x01000000;
  }
  static NetworkInterface Find(string name,string description) {
   var matches=NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.Name == name).ToArray();
   if (matches.Length == 0) return null;
   if (matches.Length != 1 || matches[0].Description != description + " Tunnel") throw new InvalidOperationException("Foreign adapter identity");
   return matches[0];
  }
  static bool Netsh(string arguments) {
   var info=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"netsh.exe"),arguments) {
    UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,
    WorkingDirectory=Environment.GetFolderPath(Environment.SpecialFolder.System)};
   NetworkBroker.CleanEnvironment(info);
   using(var process=Process.Start(info)) {
    process.StandardInput.Close(); process.OutputDataReceived+=delegate {};process.ErrorDataReceived+=delegate {};
    process.BeginOutputReadLine();process.BeginErrorReadLine();
    if(!process.WaitForExit(10000)){process.Kill();process.WaitForExit();ExitCode=-1;return false;}
    ExitCode=process.ExitCode;return ExitCode == 0;
   }
  }
  static bool Index(uint value,int v4,int v6) { return value != 0 && (value == v4 || value == v6); }
  public static bool Remove(string name,string description) {
   if(!Regex.IsMatch(name,@"^Yukiwire-[a-f0-9]{12}$") || description != "Yukiwire " + name.Substring(9)) throw new InvalidOperationException("Invalid adapter identity");
   Stage=1;ExitCode=0;
   var adapter=Find(name,description); if(adapter == null)return true;
   var properties=adapter.GetIPProperties(); int v4=properties.GetIPv4Properties().Index,v6=properties.GetIPv6Properties().Index;
   IntPtr table; uint result=GetIpForwardTable2(0,out table); if(result != 0)throw new InvalidOperationException("Route table unavailable");
   try {
    int count=Marshal.ReadInt32(table);if(count<0 || count>100000)throw new InvalidOperationException("Invalid route table");
    for(int i=0;i<count;i++) {
     IntPtr pointer=IntPtr.Add(table,8+i*Marshal.SizeOf(typeof(Route)));var row=(Route)Marshal.PtrToStructure(pointer,typeof(Route));
     if(Index(row.index,v4,v6) && Capture(row.prefix) && row.metric == 0 && Zero(row.hop)) {
      result=DeleteIpForwardEntry2(pointer);if(result != 0 && result != 1168)throw new InvalidOperationException("Route cleanup failed");
     }
    }
   } finally {FreeMibTable(table);}
   Stage=2;result=GetUnicastIpAddressTable(0,out table);if(result != 0)throw new InvalidOperationException("Address table unavailable");
   try {
    int count=Marshal.ReadInt32(table);if(count<0 || count>100000)throw new InvalidOperationException("Invalid address table");
    for(int i=0;i<count;i++) {
     IntPtr pointer=IntPtr.Add(table,8+i*Marshal.SizeOf(typeof(Unicast)));var row=(Unicast)Marshal.PtrToStructure(pointer,typeof(Unicast));
     if(Index(row.index,v4,v6) && OwnAddress(row)) {
      result=DeleteUnicastIpAddressEntry(pointer);if(result != 0 && result != 1168)throw new InvalidOperationException("Address cleanup failed");
     }
    }
   } finally {FreeMibTable(table);}
   Stage=3;if(Find(name,description) == null)return true;
   if(!Netsh("interface ipv4 set dnsservers name=\"" + name + "\" source=dhcp"))return false;
   Stage=4;if(Find(name,description) == null)return true;
   if(!Netsh("interface set interface name=\"" + name + "\" admin=disabled"))return false;
   Stage=5;adapter=Find(name,description);
   return adapter == null || adapter.OperationalStatus != OperationalStatus.Up && adapter.GetIPProperties().DnsAddresses.Count == 0;
  }
 }
}
