using System;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace Yukiwire {
 // This policy is also compiled into a non-elevated test harness. Unknown fields
 // fail closed: adding a core feature requires reviewing its privileged effects.
 public static class NetworkPolicy {
  public const int Limit = 4 * 1024 * 1024;
  public static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = Limit, RecursionLimit = 48 };
  static readonly HashSet<string> dataKeys = Set(@"address port users servers vnext id encryption flow alterId security level email password method uot UoT ivCheck
   network serverName fingerprint allowInsecure alpn publicKey password shortId spiderX mldsa65Verify show
   network security tlsSettings realitySettings tcpSettings rawSettings wsSettings grpcSettings httpupgradeSettings xhttpSettings splithttpSettings sockopt
   host path mode headers serviceName multiMode authority idle_timeout health_check_timeout permit_without_stream initial_windows_size
   acceptProxyProtocol heartbeatPeriod maxEarlyData earlyDataHeaderName
   extra xmux downloadSettings noSSEHeader noGRPCHeader xPaddingBytes scMaxEachPostBytes scMinPostsIntervalMs scMaxBufferedPosts scStreamUpServerSecs
   maxConcurrency maxConnections cMaxReuseTimes hMaxRequestTimes hMaxReusableSecs hKeepAlivePeriod
   sessionIDPlacement sessionIDKey seqPlacement seqKey uplinkDataPlacement uplinkDataKey uplinkChunkSize
   xPaddingObfsMode xPaddingKey xPaddingHeader xPaddingPlacement xPaddingMethod
   tcpFastOpen tcpKeepAliveInterval tcpKeepAliveIdle tcpUserTimeout tcpCongestion tcpMptcp tcpNoDelay domainStrategy dialerProxy happyEyeballs
   tryDelayMs prioritizeIPv6 interleave enable maxConcurrentTry interface mark tproxy tcpWindowClamp
   enabled concurrency xudpConcurrency xudpProxyUDP443 packetEncoding
   auth user pass udp ip accounts timeout userLevel allowTransparent followRedirect
   redirect fragment packets length interval maxSplit noise type delay domainStrategy userLevel response
   tag inboundTag outboundTag balancerTag domain ip port network protocol source sourcePort user process attrs
   servers hosts queryStrategy disableCache disableFallback disableFallbackIfMatch expectedIPs skipFallback domains
   address port domains expectIPs unexpectedIPs clientIp tag queryStrategy timeoutMs finalQuery
   statsInboundUplink statsInboundDownlink statsOutboundUplink statsOutboundDownlink statsUserUplink statsUserDownlink
   handshake connIdle uplinkOnly downlinkOnly bufferSize
   enabled destOverride domainsExcluded metadataOnly routeOnly
   version hysteriaSettings udpIdleTimeout finalmask settings pinnedPeerCertSha256 echConfigList
   kcpSettings mtu tti uplinkCapacity downlinkCapacity cwndMultiplier maxSendingWindow
   noKernelTun secretKey peers preSharedKey endpoint keepAlive allowedIPs reserved remoteDNS");
  static HashSet<string> Set(string words) { return new HashSet<string>(words.Split((char[])null,StringSplitOptions.RemoveEmptyEntries),StringComparer.Ordinal); }
  public static Dictionary<string,object> Map(object value) {
   var result = value as Dictionary<string,object>;
   if (result == null) throw new InvalidOperationException("Expected object"); return result;
  }
  static IEnumerable Items(object value) {
   if (!(value is object[]) && !(value is ArrayList)) throw new InvalidOperationException("Expected array");
   return (IEnumerable)value;
  }
  static void Keys(Dictionary<string,object> map,string allowed) {
   var keys = Set(allowed); foreach (string key in map.Keys) if (!keys.Contains(key)) throw new InvalidOperationException("Unsupported field");
  }
  static string Text(Dictionary<string,object> map,string key) {
   object value; return map.TryGetValue(key,out value) && value is string ? (string)value : "";
  }
  static void Data(object value,int depth) {
   if (depth > 40) throw new InvalidOperationException("Configuration too deep");
   var map = value as Dictionary<string,object>;
   if (map != null) {
    foreach (var pair in map) {
     if (!dataKeys.Contains(pair.Key)) throw new InvalidOperationException("Unsupported nested field");
     if (pair.Key == "allowInsecure" && !Object.Equals(pair.Value,false)) throw new InvalidOperationException("TLS verification required");
     if (pair.Key == "finalmask") {
      var mask = Map(pair.Value); Keys(mask,"udp");
      foreach (object item in Items(mask["udp"])) {
       var entry = Map(item); Keys(entry,"type settings");
       if (Text(entry,"type") != "salamander") throw new InvalidOperationException("Unsupported UDP mask");
       Keys(Map(entry["settings"]),"password");
      }
     }
     if (pair.Key == "headers" || pair.Key == "hosts") {
      // Header/hostname names are data, not Xray configuration keys.
      foreach (var entry in Map(pair.Value)) {
       if (pair.Key == "headers" && !(entry.Value is string)) throw new InvalidOperationException("Invalid header");
       if (pair.Key == "hosts" && !(entry.Value is string)) foreach (object item in Items(entry.Value)) if (!(item is string)) throw new InvalidOperationException("Invalid host");
      }
     } else Data(pair.Value,depth + 1);
    }
   } else if (value is object[] || value is ArrayList) foreach (object item in (IEnumerable)value) Data(item,depth + 1);
   else if (value is string) {
    string text = (string)value;
    // Only the application's two geodata files may be read via ext: rules.
    if (text.StartsWith("ext:",StringComparison.OrdinalIgnoreCase) && !Regex.IsMatch(text,@"^ext:(\.\./rulesets/[a-f0-9]{40}/)?geo(site|ip)\.dat:[a-zA-Z0-9@!_-]+$")) throw new InvalidOperationException("Unsafe geodata path");
   }
  }
  public static string Validate(string input,string adapter,string description,bool allowLocal) {
   if (input.Length > Limit || !Regex.IsMatch(adapter,@"^Yukiwire-[a-f0-9]{12}$") || description != "Yukiwire " + adapter.Substring(9)) throw new InvalidOperationException("Invalid session");
   var config = Map(Json.DeserializeObject(input));
   Keys(config,"log inbounds outbounds routing dns policy stats metrics");
   config["log"] = new Dictionary<string,object> { {"loglevel","warning"} };
   var tags = new HashSet<string>(); var ports = new HashSet<int>(); int tunCount = 0;
   foreach (object item in Items(config["inbounds"])) {
    var inbound = Map(item); Keys(inbound,"tag listen port protocol settings sniffing");
    string tag = Text(inbound,"tag"), protocol = Text(inbound,"protocol");
    if (!tags.Add(tag)) throw new InvalidOperationException("Duplicate inbound");
    if (protocol == "tun") {
     if (tag != "yukiwire-tun") throw new InvalidOperationException("Invalid TUN");
     tunCount++;
     // The caller cannot choose addresses/routes/interfaces or WFP options.
     inbound.Remove("listen"); inbound.Remove("port");
     inbound["settings"] = new Dictionary<string,object> {
      {"name",adapter},{"desc",description},{"mtu",1500},
      {"gateway",new [] {"172.29.250.1/30","fd72:756b:6977::1/126"}}, {"dns",new [] {"172.29.250.2"}},
      {"autoSystemRoutingTable",new [] {"0.0.0.0/1","128.0.0.0/1","::/1","8000::/1"}},
      {"autoOutboundsInterface","auto"},{"autoSystemWfpBlockLeak",new [] {"dns","misconfigtun"}}
     };
    } else {
     if (Text(inbound,"listen") != "127.0.0.1" || !Set("local-http local-socks yukiwire-check yukiwire-metrics").Contains(tag)) throw new InvalidOperationException("Invalid listener");
     int port; if (!Int32.TryParse(Convert.ToString(inbound["port"]),out port) || port < 1024 || port > 65535 || !ports.Add(port)) throw new InvalidOperationException("Invalid port");
     if (protocol != (tag == "local-socks" ? "socks" : "http")) throw new InvalidOperationException("Invalid listener protocol");
     var settings = Map(inbound["settings"]); Keys(settings,protocol == "socks" ? "auth accounts udp" : "accounts");
     if (tag != "local-http") {
      if (!settings.ContainsKey("accounts")) throw new InvalidOperationException("Authentication required");
      int count = 0;
      foreach (object entry in Items(settings["accounts"])) {
       var account = Map(entry); Keys(account,"user pass");
       if (Text(account,"user").Length < 1 || Text(account,"pass").Length < 32) throw new InvalidOperationException("Weak credentials"); count++;
      }
      if (count != 1 || protocol == "socks" && (Text(settings,"auth") != "password" || !Object.Equals(settings["udp"],false))) throw new InvalidOperationException("Invalid authentication");
     }
    }
    if (inbound.ContainsKey("sniffing")) Data(inbound["sniffing"],0);
   }
   if (tunCount != (allowLocal ? 0 : 1)) throw new InvalidOperationException("Exactly one managed TUN required");
   int outboundCount = 0;
   foreach (object item in Items(config["outbounds"])) {
    var outbound = Map(item); Keys(outbound,"tag protocol settings streamSettings mux proxySettings sendThrough");
    if (!Set("vless vmess trojan shadowsocks hysteria wireguard socks http freedom blackhole dns loopback").Contains(Text(outbound,"protocol"))) throw new InvalidOperationException("Unsupported outbound");
    if (Text(outbound,"protocol") == "wireguard") { var settings = Map(outbound["settings"]); if (!settings.ContainsKey("noKernelTun") || !Object.Equals(settings["noKernelTun"],true)) throw new InvalidOperationException("Userspace WireGuard required"); }
    foreach (var pair in outbound) if (pair.Key != "protocol" && pair.Key != "tag") Data(pair.Value,0);
    outboundCount++;
   }
   if (outboundCount < 1 || outboundCount > 32) throw new InvalidOperationException("Invalid outbound count");
   if (config.ContainsKey("dns")) { Keys(Map(config["dns"]),"servers hosts queryStrategy tag clientIp disableCache disableFallback disableFallbackIfMatch"); Data(config["dns"],0); }
   if (config.ContainsKey("routing")) { var routing = Map(config["routing"]); Keys(routing,"domainStrategy domainMatcher rules"); Data(routing["rules"],0); }
   if (config.ContainsKey("metrics")) { var metrics = Map(config["metrics"]); Keys(metrics,"tag"); if (Text(metrics,"tag") != "yukiwire-stats") throw new InvalidOperationException("Invalid metrics"); }
   if (config.ContainsKey("stats")) Keys(Map(config["stats"]),"");
   if (config.ContainsKey("policy")) {
    var policy = Map(config["policy"]); Keys(policy,"levels system");
    if (policy.ContainsKey("system")) Data(policy["system"],0);
    if (policy.ContainsKey("levels")) foreach (var level in Map(policy["levels"])) { uint number; if (!UInt32.TryParse(level.Key,out number)) throw new InvalidOperationException("Invalid level"); Data(level.Value,0); }
   }
   return Json.Serialize(config);
  }
 }
}
