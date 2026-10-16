using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;

namespace Yukiwire {
 public static class ProtectedStorage {
  public static string ProgramFiles { get { return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles); } }
  public static string Root { get { return Path.Combine(ProgramFiles,"YukiwireNetwork"); } }
  public static string DirectoryPath { get { return Path.Combine(Root,NetworkBuild.Identity); } }
  static readonly SecurityIdentifier Admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
  static readonly SecurityIdentifier System = new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
  static readonly SecurityIdentifier Users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid,null);
  static bool Trusted(string sid) {
   return sid == Admin.Value || sid == System.Value || sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
  }
  public static void Verify(string path) {
   FileAttributes attributes = File.GetAttributes(path);
   if ((attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Reparse point in helper installation");
   FileSystemSecurity security = (attributes & FileAttributes.Directory) != 0 ? (FileSystemSecurity)Directory.GetAccessControl(path) : File.GetAccessControl(path);
   if (!Trusted(security.GetOwner(typeof(SecurityIdentifier)).Value)) throw new InvalidOperationException("Untrusted helper owner");
   var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(),0);
   if (descriptor.DiscretionaryAcl == null) throw new InvalidOperationException("Missing helper DACL");
   foreach (GenericAce generic in descriptor.DiscretionaryAcl) {
    if ((generic.AceFlags & AceFlags.InheritOnly) != 0) continue;
    var ace = generic as CommonAce;
    if (ace == null || ace.IsCallback) throw new InvalidOperationException("Unsupported helper ACL");
    if (ace.AceQualifier == AceQualifier.AccessDenied) continue;
    if (ace.AceQualifier != AceQualifier.AccessAllowed || ((unchecked((uint)ace.AccessMask) & 0x500D0156U) != 0 && !Trusted(ace.SecurityIdentifier.Value))) throw new InvalidOperationException("Writable helper installation");
   }
  }
  public static void VerifyChain() {
   Verify(ProgramFiles); Verify(Root); Verify(DirectoryPath);
  }
  public static void CreateDirectory(string path) {
   if (!Directory.Exists(path)) {
    var security = new DirectorySecurity(); security.SetAccessRuleProtection(true,false); security.SetOwner(Admin);
    foreach (SecurityIdentifier sid in new [] {Admin,System}) security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
    security.AddAccessRule(new FileSystemAccessRule(Users,FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
    Directory.CreateDirectory(path,security);
   }
   Verify(path);
  }
  public static void OwnFile(string path) {
   var security = new FileSecurity(); security.SetAccessRuleProtection(true,false); security.SetOwner(Admin);
   foreach (SecurityIdentifier sid in new [] {Admin,System}) security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,AccessControlType.Allow));
   security.AddAccessRule(new FileSystemAccessRule(Users,FileSystemRights.ReadAndExecute,AccessControlType.Allow));
   File.SetAccessControl(path,security); Verify(path);
  }
  public static string Digest(string path) {
   using (var hash = SHA256.Create()) using (var stream = File.OpenRead(path)) return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
  }
 }
}
