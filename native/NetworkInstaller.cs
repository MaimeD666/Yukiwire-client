using System;
using System.IO;
using System.Reflection;
using System.Security.Principal;

namespace Yukiwire {
 public static class NetworkInstaller {
  [STAThread] public static int Main(string[] args) {
   if (args.Length != 0 || !new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return 2;
   try {
    ProtectedStorage.Verify(ProtectedStorage.ProgramFiles);
    ProtectedStorage.CreateDirectory(ProtectedStorage.Root);
    ProtectedStorage.CreateDirectory(ProtectedStorage.DirectoryPath);
    for (int index = 0; index < NetworkBuild.Names.Length; index++) {
     string target = Path.Combine(ProtectedStorage.DirectoryPath,NetworkBuild.Names[index]);
     if (File.Exists(target)) {
      ProtectedStorage.Verify(target);
      if (ProtectedStorage.Digest(target) == NetworkBuild.Hashes[index]) continue;
      // Never update an existing version in place; refuse corruption or collisions.
      throw new InvalidOperationException("Existing component does not match this version");
     }
     using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream(NetworkBuild.Names[index]))
     using (var output = new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.None)) { input.CopyTo(output); output.Flush(true); }
     ProtectedStorage.OwnFile(target);
     if (ProtectedStorage.Digest(target) != NetworkBuild.Hashes[index]) throw new InvalidOperationException("Component integrity failure");
    }
    return 0;
   } catch (Exception) { return 4; }
  }
 }
}
