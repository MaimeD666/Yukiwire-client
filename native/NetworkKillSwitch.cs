using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Yukiwire {
 public sealed class NetworkKillSwitch : IDisposable {
  [DllImport("iphlpapi.dll",CharSet=CharSet.Unicode)] static extern uint ConvertInterfaceAliasToLuid(string alias,out ulong luid);
  readonly string path;
  readonly Process owner;
  readonly NetworkFilter filter;
  public bool Active { get { return File.Exists(path); } }
  public NetworkKillSwitch(string sid,Process owner) {
   this.owner = owner;
   string directory = Path.Combine(ProtectedStorage.DirectoryPath,"protection"); ProtectedStorage.CreateDirectory(directory);
   // SID comes from the verified parent token, never from a request.
   path = Path.Combine(directory,sid + ".json");
   filter = new NetworkFilter(NetworkBuild.Identity + ":" + sid,Path.Combine(ProtectedStorage.DirectoryPath,"xray.exe"));
  }
  void CheckOwner() {
   if (!Active) return;
   ProtectedStorage.Verify(path);
   if (new FileInfo(path).Length > 1024) throw new InvalidOperationException("Invalid protection record");
   var record = NetworkPolicy.Map(NetworkPolicy.Json.DeserializeObject(File.ReadAllText(path,Encoding.UTF8)));
   int pid = Convert.ToInt32(record["owner"]); long start = Convert.ToInt64(record["start"]);
   if (pid == owner.Id && start == owner.StartTime.ToUniversalTime().ToFileTimeUtc()) return;
   try { using (var process = Process.GetProcessById(pid)) if (!process.HasExited && process.StartTime.ToUniversalTime().ToFileTimeUtc() == start) throw new InvalidOperationException("Another owner holds protection"); }
   catch (ArgumentException) {}
  }
  public void Arm() {
   CheckOwner();
   byte[] data = Encoding.UTF8.GetBytes(NetworkPolicy.Json.Serialize(new Dictionary<string,object> { {"owner",owner.Id}, {"start",owner.StartTime.ToUniversalTime().ToFileTimeUtc()} }));
   string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
   try {
    using (var stream = new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)) { stream.Write(data,0,data.Length); stream.Flush(true); }
    ProtectedStorage.OwnFile(temporary);
    if (Active) File.Replace(temporary,path,null); else File.Move(temporary,path);
   } finally { if (File.Exists(temporary)) File.Delete(temporary); }
   // Journal first. Failed transactions keep the previous policy and a recovery record.
   filter.Apply(0);
  }
  public void PermitTun(string adapter) {
   if (!Active) return; CheckOwner(); ulong luid;
   if (String.IsNullOrEmpty(adapter) || ConvertInterfaceAliasToLuid(adapter,out luid) != 0 || luid == 0) throw new InvalidOperationException("TUN interface unavailable");
   filter.Apply(luid);
  }
  public void BlockTun() { if (Active) { CheckOwner(); filter.Apply(0); } }
  public void Release() { CheckOwner(); filter.Remove(); if (Active) File.Delete(path); }
  // A crash/EOF preserves filters. Only an explicit release/recovery removes them.
  public void Dispose() { filter.Dispose(); }
 }
}
