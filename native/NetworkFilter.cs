using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Yukiwire {
 // Persistent WFP objects are changed in one transaction. Closing the RPC session
 // (including helper death) does not remove the policy. No global firewall settings.
 public sealed class NetworkFilter : IDisposable {
  [StructLayout(LayoutKind.Sequential)] public struct Display { [MarshalAs(UnmanagedType.LPWStr)] public string name, description; }
  [StructLayout(LayoutKind.Sequential)] public struct Blob { public uint size; public IntPtr data; }
  [StructLayout(LayoutKind.Explicit,Size=16)] public struct Value { [FieldOffset(0)] public uint type; [FieldOffset(8)] public ulong number; [FieldOffset(8)] public IntPtr pointer; }
  [StructLayout(LayoutKind.Sequential)] public struct Condition { public Guid field; public uint match; public Value value; }
  [StructLayout(LayoutKind.Sequential)] public struct Action { public uint type; public Guid key; }
  [StructLayout(LayoutKind.Explicit,Size=16)] public struct Context { [FieldOffset(0)] public ulong raw; [FieldOffset(0)] public Guid key; }
  [StructLayout(LayoutKind.Sequential)] public struct Filter {
   public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob data;
   public Guid layer, sublayer; public Value weight; public uint count; public IntPtr conditions;
   public Action action; public Context context; public IntPtr reserved; public ulong id; public Value effectiveWeight;
  }
  [StructLayout(LayoutKind.Sequential)] public struct Sublayer { public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob data; public ushort weight; }
  [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine,ref Sublayer layer,IntPtr security);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerGetByKey0(IntPtr engine,ref Guid key,out IntPtr value);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine,ref Guid key);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine,ref Filter filter,IntPtr security,out ulong id);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine,ref Guid key,out IntPtr value);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
  [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file,out IntPtr blob);
  [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
  public static readonly Guid[] Layers = {
   new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"),
   new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f")
  };
  static readonly Guid App = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971"), Flags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c"),
   Next = new Guid("93ae8f5b-7f6f-4719-98c8-14e97429ef04"), Arrival = new Guid("618a9b6d-386b-4136-ad6e-b51587cfb1cd"),
   Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"), LocalPort = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b"),
   RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
  const string Label = "Yukiwire connection protection";
  readonly string identity, executable;
  Guid sublayer;
  IntPtr engine;
  public NetworkFilter(string identity,string executable) { this.identity = identity; this.executable = executable; sublayer = Key("sublayer"); }
  Guid Key(string role) {
   using (var hash = SHA256.Create()) { byte[] digest = hash.ComputeHash(Encoding.UTF8.GetBytes("Yukiwire.WFP.v1:" + identity + ":" + role)); byte[] bytes = new byte[16]; Array.Copy(digest,bytes,16); return new Guid(bytes); }
  }
  static void Check(uint code) { if (code != 0) throw new InvalidOperationException("WFP operation failed: " + code.ToString("x8")); }
  void Open() { if (engine == IntPtr.Zero) Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine)); }
  void Delete(string role) {
   Guid key = Key(role); IntPtr pointer; uint result = FwpmFilterGetByKey0(engine,ref key,out pointer);
   if (result == 0x80320003) return; // FWP_E_FILTER_NOT_FOUND
   Check(result);
   try { var existing = (Filter)Marshal.PtrToStructure(pointer,typeof(Filter)); if (existing.sublayer != sublayer || existing.display.name != Label) throw new InvalidOperationException("Foreign filter identity"); }
   finally { FwpmFreeMemory0(ref pointer); }
   Check(FwpmFilterDeleteByKey0(engine,ref key));
  }
  bool HasSublayer() {
   IntPtr pointer; uint result = FwpmSubLayerGetByKey0(engine,ref sublayer,out pointer);
   if (result == 0x80320007) return false; // FWP_E_SUBLAYER_NOT_FOUND
   Check(result);
   try { if (((Sublayer)Marshal.PtrToStructure(pointer,typeof(Sublayer))).display.name != Label) throw new InvalidOperationException("Foreign sublayer identity"); }
   finally { FwpmFreeMemory0(ref pointer); }
   return true;
  }
  static Condition Number(Guid field,uint type,ulong number,uint match) { return new Condition { field = field, match = match, value = new Value { type = type, number = number } }; }
  void Add(string role,int layer,bool permit,byte weight,params Condition[] conditions) {
   IntPtr buffer = IntPtr.Zero;
   try {
    if (conditions.Length > 0) {
     int size = Marshal.SizeOf(typeof(Condition)); buffer = Marshal.AllocHGlobal(size * conditions.Length);
     for (int i = 0; i < conditions.Length; i++) Marshal.StructureToPtr(conditions[i],IntPtr.Add(buffer,i * size),false);
    }
    // Interface LUIDs must not become stale permits after a reboot/BFE restart.
    // Static TUN permits outlive this helper, but not the BFE; the blocks persist.
    var filter = new Filter { key = Key(role), display = new Display { name = Label }, flags = role.StartsWith("tun",StringComparison.Ordinal) ? 0U : 1U, layer = Layers[layer], sublayer = sublayer,
     weight = new Value { type = 1, number = weight }, count = (uint)conditions.Length, conditions = buffer,
     action = new Action { type = permit ? 0x1002U : 0x1001U } };
    ulong id; Check(FwpmFilterAdd0(engine,ref filter,IntPtr.Zero,out id));
   } finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
  }
  // Every owned key is deterministic, so recovery works even after a crash
  // between committing WFP and reporting success over the pipe.
  public void Apply(ulong tunInterface) {
   Open(); IntPtr app = IntPtr.Zero, luid = IntPtr.Zero;
   Check(FwpmGetAppIdFromFileName0(executable,out app));
   try {
    luid = Marshal.AllocHGlobal(8); Marshal.WriteInt64(luid,unchecked((long)tunInterface));
    Check(FwpmTransactionBegin0(engine,0));
    try {
     if (!HasSublayer()) { var layer = new Sublayer { key = sublayer, display = new Display { name = Label }, flags = 1, weight = 0x100 }; Check(FwpmSubLayerAdd0(engine,ref layer,IntPtr.Zero)); }
     for (int i = 0; i < Layers.Length; i++) {
      foreach (string role in new [] {"app","loopback","dhcp","tun","block"}) Delete(role + i);
      Add("app" + i,i,true,15,new Condition { field = App, value = new Value { type = 12, pointer = app } });
      Add("loopback" + i,i,true,14,Number(Flags,3,1,6)); // FWP_MATCH_FLAGS_ALL_SET, IS_LOOPBACK
      Add("dhcp" + i,i,true,13,Number(Protocol,1,17,0),Number(LocalPort,2,(ulong)(i % 2 == 0 ? 68 : 546),0),Number(RemotePort,2,(ulong)(i % 2 == 0 ? 67 : 547),0));
      if (tunInterface != 0) Add("tun" + i,i,true,12,new Condition { field = i < 2 ? Next : Arrival, value = new Value { type = 4, pointer = luid } });
      Add("block" + i,i,false,1);
     }
     Check(FwpmTransactionCommit0(engine));
    } catch { FwpmTransactionAbort0(engine); throw; }
   } finally { if (app != IntPtr.Zero) FwpmFreeMemory0(ref app); if (luid != IntPtr.Zero) Marshal.FreeHGlobal(luid); }
  }
  public void Remove() {
   Open(); Check(FwpmTransactionBegin0(engine,0));
   try {
    for (int i = 0; i < Layers.Length; i++) foreach (string role in new [] {"app","loopback","dhcp","tun","block"}) Delete(role + i);
    if (HasSublayer()) Check(FwpmSubLayerDeleteByKey0(engine,ref sublayer));
    Check(FwpmTransactionCommit0(engine));
   } catch { FwpmTransactionAbort0(engine); throw; }
  }
  public void Dispose() { if (engine != IntPtr.Zero) { FwpmEngineClose0(engine); engine = IntPtr.Zero; } }
 }
}
