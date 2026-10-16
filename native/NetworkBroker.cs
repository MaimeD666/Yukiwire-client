using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Yukiwire {
 public sealed class NetworkBroker : IDisposable {
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeServerProcessId(IntPtr pipe,out uint pid);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr security,string name);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,IntPtr info,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern bool SetDllDirectory(string path);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  readonly object stateLock = new object(), writeLock = new object();
  readonly Process parent;
  readonly NamedPipeClientStream pipe;
  readonly string ownerSid;
  readonly long ownerStart;
  readonly NetworkKillSwitch protection;
  Process core;
  IntPtr job;
  string adapter,description,lease,assetFolder;
  int serial;
  string pendingConfig;
  bool disposed;
  void Diagnostic(string line,int generation) {
   if (String.IsNullOrEmpty(line)) return;
   string text = line.ToLowerInvariant();
   string category = "other";
   if (text.Contains("certificate") || text.Contains("x509") || text.Contains("handshake") || text.Contains("reality")) category = "tls";
   else if (text.Contains("dns") || text.Contains("lookup") || text.Contains("resolve")) category = "dns";
   else if (text.Contains("timeout") || text.Contains("deadline")) category = "timeout";
   else if (text.Contains("refused")) category = "refused";
   else if (text.Contains("permission") || text.Contains("forbidden") || text.Contains("access denied")) category = "permission";
   else if (text.Contains("connection reset")) category = "reset";
   else if (text.Contains("configuration") || text.Contains("config:")) category = "config";
   else if (text.Contains("transport")) category = "transport";
   else if (text.Contains("connection") || text.Contains("failed to")) category = "connection";
   string level = text.Contains("[error]") ? "error" : text.Contains("[warning]") ? "warning" : "info";
   try { Write(ObjectOf("event","diagnostic","serial",generation,"category",category,"level",level,"module","core")); } catch (Exception) {}
  }

  NetworkBroker(Process owner,NamedPipeClientStream channel) {
   parent = owner; pipe = channel; ownerStart = parent.StartTime.ToUniversalTime().ToFileTimeUtc();
   IntPtr token;
   if (!OpenProcessToken(parent.Handle,0xA,out token)) throw new InvalidOperationException("Cannot identify owner");
   try { using (var identity = new WindowsIdentity(token)) ownerSid = identity.User.Value; }
   finally { CloseHandle(token); }
   protection = new NetworkKillSwitch(ownerSid,parent);
  }
  static Dictionary<string,object> ObjectOf(params object[] pairs) {
   var result = new Dictionary<string,object>(); for (int i = 0; i < pairs.Length; i += 2) result[(string)pairs[i]] = pairs[i+1]; return result;
  }
  static string StringOf(Dictionary<string,object> value,string key) {
   object result; if (!value.TryGetValue(key,out result) || !(result is string)) throw new InvalidOperationException("Missing field"); return (string)result;
  }
  void Write(object value) {
   lock (writeLock) {
    byte[] data = Encoding.UTF8.GetBytes(NetworkPolicy.Json.Serialize(value));
    byte[] length = BitConverter.GetBytes(data.Length); pipe.Write(length,0,4); pipe.Write(data,0,data.Length); pipe.Flush();
   }
  }
  byte[] Read(int length) {
   byte[] data = new byte[length]; int done = 0;
   while (done < length) { int count = pipe.Read(data,done,length-done); if (count == 0) throw new EndOfStreamException(); done += count; }
   return data;
  }
  static bool Alive(int pid,long start) {
   try { using (var process = Process.GetProcessById(pid)) return !process.HasExited && process.StartTime.ToUniversalTime().ToFileTimeUtc() == start; }
   catch (ArgumentException) { return false; }
  }
  static void CheckPayload() {
   ProtectedStorage.VerifyChain();
   string self = Process.GetCurrentProcess().MainModule.FileName;
   if (!String.Equals(self,Path.Combine(ProtectedStorage.DirectoryPath,"Yukiwire.Network.exe"),StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Protected installation required");
   ProtectedStorage.Verify(self);
   for (int i = 0; i < NetworkBuild.Names.Length; i++) {
    string path = Path.Combine(ProtectedStorage.DirectoryPath,NetworkBuild.Names[i]); ProtectedStorage.Verify(path);
    if (ProtectedStorage.Digest(path) != NetworkBuild.Hashes[i]) throw new InvalidOperationException("Damaged network component");
   }
  }
  static bool CleanupAdapter(string name,string desc) { return NetworkCleanup.Remove(name,desc); }
  internal static void CleanEnvironment(ProcessStartInfo info) {
   // No caller-controlled core configuration, DLL/plugin search, PowerShell modules,
   // or Go runtime diagnostics. Start from a small OS environment.
   info.EnvironmentVariables.Clear();
   string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
   info.EnvironmentVariables["SystemRoot"] = windows; info.EnvironmentVariables["WINDIR"] = windows;
   info.EnvironmentVariables["PATH"] = Environment.GetFolderPath(Environment.SpecialFolder.System);
   info.EnvironmentVariables["TEMP"] = Path.Combine(windows,"Temp"); info.EnvironmentVariables["TMP"] = Path.Combine(windows,"Temp");
   info.EnvironmentVariables["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),@"WindowsPowerShell\v1.0\Modules");
  }
  void Recover() {
   string folder = Path.Combine(ProtectedStorage.DirectoryPath,"leases"); ProtectedStorage.CreateDirectory(folder);
   foreach (string path in Directory.GetFiles(folder,"*.json")) {
    ProtectedStorage.Verify(path);
    if (new FileInfo(path).Length > 4096) throw new InvalidOperationException("Invalid recovery record");
    var record = NetworkPolicy.Map(NetworkPolicy.Json.DeserializeObject(File.ReadAllText(path,Encoding.UTF8)));
    if (StringOf(record,"sid") != ownerSid) continue;
    if (Alive(Convert.ToInt32(record["core"]),Convert.ToInt64(record["core_start"]))) continue;
    bool sameOwner = Convert.ToInt32(record["owner"]) == parent.Id && Convert.ToInt64(record["owner_start"]) == ownerStart;
    if (!sameOwner && Alive(Convert.ToInt32(record["owner"]),Convert.ToInt64(record["owner_start"]))) continue;
    if (!record.ContainsKey("tun") || !Object.Equals(record["tun"],false)) {
     if (!CleanupAdapter(StringOf(record,"adapter"),StringOf(record,"description"))) throw new InvalidOperationException("Recovery incomplete");
    }
    File.Delete(path);
   }
  }
  static void AssetReferences(object value,HashSet<string> files) {
   var map = value as Dictionary<string,object>;
   if (map != null) { foreach (var pair in map) AssetReferences(pair.Value,files); }
   else if (value is object[] || value is ArrayList) { foreach (object entry in (IEnumerable)value) AssetReferences(entry,files); }
   else if (value is string) {
    string text = (string)value;
    if (text.StartsWith("geosite:",StringComparison.Ordinal)) files.Add("core/geosite.dat");
    if (text.StartsWith("geoip:",StringComparison.Ordinal)) files.Add("core/geoip.dat");
    var match = Regex.Match(text,@"^ext:(\.\./rulesets/[a-f0-9]{40}/)?(geo(site|ip)\.dat):");
    if (match.Success) files.Add(match.Groups[1].Success ? match.Groups[1].Value.Substring(3) + match.Groups[2].Value : "core/" + match.Groups[2].Value);
   }
  }
  string PrepareAssets(string source,string config) {
   if (!Path.IsPathRooted(source) || source.StartsWith(@"\\") || source.IndexOf('"') >= 0) throw new InvalidOperationException("Invalid asset directory");
   source = Path.GetFullPath(source);
   var files = new HashSet<string>(); AssetReferences(NetworkPolicy.Json.DeserializeObject(config),files);
   string folder = Path.Combine(ProtectedStorage.DirectoryPath,"assets"); ProtectedStorage.CreateDirectory(folder);
   folder = Path.Combine(folder,Guid.NewGuid().ToString("N")); ProtectedStorage.CreateDirectory(folder);
   assetFolder = folder;
   ProtectedStorage.CreateDirectory(Path.Combine(folder,"core"));
   foreach (string relative in files) {
    string input = Path.GetFullPath(Path.Combine(source,relative)); byte[] bytes;
    IntPtr token; if (!OpenProcessToken(parent.Handle,0xA,out token)) throw new InvalidOperationException("Cannot read caller assets");
    try {
     // The elevated process must not read a file unavailable to the caller,
     // including through symlinks or a junction supplied as a data directory.
     using (WindowsImpersonationContext context = WindowsIdentity.Impersonate(token)) {
      using (var stream = File.OpenRead(input)) {
       if (stream.Length > 128 * 1024 * 1024) throw new InvalidOperationException("Asset too large");
       using (var buffer = new MemoryStream()) { stream.CopyTo(buffer); bytes = buffer.ToArray(); }
      }
     }
    } finally { CloseHandle(token); }
    string target = Path.Combine(folder,relative);
    string current = folder;
    string[] segments = relative.Split('/');
    for (int i = 0; i < segments.Length - 1; i++) { current = Path.Combine(current,segments[i]); ProtectedStorage.CreateDirectory(current); }
    using (var output = new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None)) { output.Write(bytes,0,bytes.Length); output.Flush(true); }
    ProtectedStorage.OwnFile(target);
   }
   return Path.Combine(folder,"core");
  }
  object Prepare(Dictionary<string,object> request) {
   if (core != null || lease != null) throw new InvalidOperationException("Previous session needs cleanup");
   CheckPayload(); Recover();
   string token = Guid.NewGuid().ToString("N").Substring(0,12);
   adapter = "Yukiwire-" + token; description = "Yukiwire " + token;
   // The helper chooses the identity. Return it before the caller arms its journal.
   bool local = request.ContainsKey("local") && Object.Equals(request["local"],true);
   pendingConfig = NetworkPolicy.Validate(StringOf(request,"config"),adapter,description,local);
   if (local) { adapter = null; description = null; }
   string assets = PrepareAssets(StringOf(request,"assets"),pendingConfig);
   job = CreateJobObject(IntPtr.Zero,null); if (job == IntPtr.Zero) throw new InvalidOperationException("Cannot create core job");
   // JOBOBJECT_EXTENDED_LIMIT_INFORMATION on x64: BasicLimitFlags offset 16.
   IntPtr limits = Marshal.AllocHGlobal(144);
   try { for (int i = 0; i < 144; i++) Marshal.WriteByte(limits,i,0); Marshal.WriteInt32(limits,16,0x2000); if (!SetInformationJobObject(job,9,limits,144)) throw new InvalidOperationException("Cannot protect core job"); }
   finally { Marshal.FreeHGlobal(limits); }
   var info = new ProcessStartInfo(Path.Combine(ProtectedStorage.DirectoryPath,"xray.exe"),"run -format json -c stdin:") { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = ProtectedStorage.DirectoryPath, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
   CleanEnvironment(info); info.EnvironmentVariables["XRAY_LOCATION_ASSET"] = assets;
   int currentSerial = ++serial;
   core = Process.Start(info);
   core.OutputDataReceived += delegate(object sender,DataReceivedEventArgs entry) { Diagnostic(entry.Data,currentSerial); };
   core.ErrorDataReceived += delegate(object sender,DataReceivedEventArgs entry) { Diagnostic(entry.Data,currentSerial); };
   core.BeginOutputReadLine(); core.BeginErrorReadLine();
   if (!AssignProcessToJobObject(job,core.Handle)) throw new InvalidOperationException("Cannot contain core");
   lease = Path.Combine(ProtectedStorage.DirectoryPath,"leases",Guid.NewGuid().ToString("N") + ".json");
   var record = ObjectOf("sid",ownerSid,"owner",parent.Id,"owner_start",ownerStart,"core",core.Id,"core_start",core.StartTime.ToUniversalTime().ToFileTimeUtc(),"adapter",adapter,"description",description,"tun",!local);
   byte[] data = Encoding.UTF8.GetBytes(NetworkPolicy.Json.Serialize(record));
   using (var stream = new FileStream(lease,FileMode.CreateNew,FileAccess.Write,FileShare.None)) { stream.Write(data,0,data.Length); stream.Flush(true); }
   ProtectedStorage.OwnFile(lease);
   return ObjectOf("pid",core.Id,"core_start",core.StartTime.ToUniversalTime().ToFileTimeUtc(),"serial",serial,"adapter",adapter,"description",description);
  }
  void StartCore() {
   if (core == null || pendingConfig == null) throw new InvalidOperationException("No prepared core");
   byte[] data = Encoding.UTF8.GetBytes(pendingConfig); pendingConfig = null;
   core.StandardInput.BaseStream.Write(data,0,data.Length); core.StandardInput.Close();
   Process observed = core; int observedSerial = serial;
   var watch = new Thread(delegate() {
    try {
     observed.WaitForExit();
     lock (stateLock) {
      if (core != observed) return;
      int code = observed.ExitCode; bool cleaned = StopCore();
      Write(ObjectOf("event","exited","serial",observedSerial,"code",code,"cleaned",cleaned));
     }
    } catch (Exception) {
     // StopCore may dispose the observed process while this watcher wakes up.
     // A late watcher must never tear down the next session's channel.
     lock (stateLock) { if (core == observed && serial == observedSerial) { try { pipe.Dispose(); } catch (Exception) {} } }
    }
   }); watch.IsBackground = true; watch.Start();
  }
  bool StopCore() {
   pendingConfig = null;
   // Remove the TUN permit before its route can disappear. Keep the block rules.
   if (adapter != null) protection.BlockTun();
   if (core != null) {
    try { if (!core.HasExited) core.Kill(); } finally { if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; } }
    if (!core.WaitForExit(5000)) return false;
    core.Dispose(); core = null;
   } else if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; }
   if (lease != null) {
    if (adapter != null && !CleanupAdapter(adapter,description)) return false;
    File.Delete(lease); lease = null;
   }
   if (assetFolder != null) {
    // Generated under a protected directory, never a caller-supplied delete path.
    ProtectedStorage.Verify(assetFolder); Directory.Delete(assetFolder,true); assetFolder = null;
   }
   return true;
  }
  void Run() {
   var parentWatch = new Thread(delegate() { try { parent.WaitForExit(); pipe.Dispose(); } catch (Exception) {} });
   parentWatch.IsBackground = true; parentWatch.Start();
   Write(ObjectOf("event","ready","identity",NetworkBuild.Identity));
   while (true) {
    int size = BitConverter.ToInt32(Read(4),0); if (size < 2 || size > NetworkPolicy.Limit) throw new InvalidOperationException("Invalid message size");
    var request = NetworkPolicy.Map(NetworkPolicy.Json.DeserializeObject(new UTF8Encoding(false,true).GetString(Read(size))));
    object id; if (!request.TryGetValue("id",out id) || !(id is int)) throw new InvalidOperationException("Invalid request id");
    lock (stateLock) {
     try {
      object result; string action = StringOf(request,"action");
      if (action == "prepare") result = Prepare(request);
      else if (action == "start" || action == "stop" || action == "arm" || action == "permit_tun") {
       if (!request.ContainsKey("serial") || Convert.ToInt32(request["serial"]) != serial) { Write(ObjectOf("id",id,"ok",true,"result",false)); continue; }
       if (action == "start") StartCore();
       else if (action == "arm") { if (core == null || pendingConfig == null) throw new InvalidOperationException("Core not prepared"); protection.Arm(); }
       else if (action == "permit_tun") { if (core == null || core.HasExited || pendingConfig != null) throw new InvalidOperationException("Core not running"); protection.PermitTun(adapter); }
       else if (!StopCore()) throw new InvalidOperationException("Cleanup incomplete");
       result = true;
      }
      else if (action == "release") { if (core != null) throw new InvalidOperationException("Core active"); protection.Release(); result = true; }
      else if (action == "recover") { if (core != null) throw new InvalidOperationException("Core active"); CheckPayload(); Recover(); protection.Release(); result = true; }
      else if (action == "close") { if (!StopCore()) throw new InvalidOperationException("Cleanup incomplete"); Write(ObjectOf("id",id,"ok",true)); return; }
      else throw new InvalidOperationException("Unknown command");
      Write(ObjectOf("id",id,"ok",true,"result",result));
     } catch (Exception) {
      // Never send raw exceptions, paths, profiles, or Xray stderr over this API.
      bool cleaned = false; try { cleaned = StopCore(); } catch (Exception) {}
      Write(ObjectOf("id",id,"ok",false,"cleaned",cleaned,"cleanup_stage",NetworkCleanup.Stage,"cleanup_exit",NetworkCleanup.ExitCode));
     }
    }
   }
  }
  public void Dispose() { lock (stateLock) { if (disposed) return; disposed = true; try { StopCore(); } finally { if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; } protection.Dispose(); } } }
  [STAThread] public static int Main(string[] args) {
   if (args.Length != 3 || !Regex.IsMatch(args[0],@"^YukiwireCore\.[a-f0-9]{32}$")) return 2;
   int pid; long start; if (!Int32.TryParse(args[1],out pid) || !Int64.TryParse(args[2],out start)) return 2;
   if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return 3;
   try {
    SetDllDirectory(""); CheckPayload();
    using (var owner = Process.GetProcessById(pid)) {
     if (owner.HasExited || owner.StartTime.ToUniversalTime().ToFileTimeUtc() != start) return 3;
     using (var channel = new NamedPipeClientStream(".",args[0],PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification)) {
      channel.Connect(15000); uint server;
      if (!GetNamedPipeServerProcessId(channel.SafePipeHandle.DangerousGetHandle(),out server) || server != pid) return 3;
      using (var broker = new NetworkBroker(owner,channel)) broker.Run();
     }
    }
    return 0;
   } catch (EndOfStreamException) { return 0; }
   catch (Exception) { return 4; }
  }
 }
}
