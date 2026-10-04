using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Shell;
using Microsoft.Win32;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;

namespace Yukiwire {
 public sealed class WebShell : Window {
  const string Origin = "https://yukiwire.local/";
  readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 4 * 1024 * 1024 };
  readonly HashSet<string> actions = new HashSet<string> { "start", "stop", "probe", "check_sites", "save_profile", "delete_profile", "get_profile", "save_settings", "explain", "update_rules", "rollback_rules", "recover_network", "export_diagnostics", "open_browser", "refresh_environment", "get_analytics", "get_state" };
  WebView2 view = new WebView2();
  readonly string root, dataRoot, testProfile;
  readonly bool smoke, connectedSmoke;
  Process backend;
  Process browserProcess;
  Process networkWorker;
  NamedPipeServerStream workerPipe;
  StreamWriter workerInput;
  object workerPending;
  bool switchingBackend, integrationWorker;
  bool integrationCrash;
  bool integrationRenderer, integrationBrowser, rendererRecovered;
  int originalCorePid;
  System.Windows.Threading.DispatcherTimer integrationTimeout;
  int workerGeneration;
  Task workerReader;
  bool recoveringRenderer;
  bool launchingBrowser;
  System.Windows.Forms.NotifyIcon tray;
  System.Windows.Forms.ToolStripMenuItem trayConnect;
  bool closing, uiReady, backendStarted;
  int integrationPhase;
  bool integrationNetwork;
  readonly List<string> integrationEvents = new List<string>();
  [DllImport("user32.dll")] static extern bool ReleaseCapture();
  [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr hwnd, uint msg, IntPtr wparam, IntPtr lparam);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern IntPtr FindWindow(string className,string name);
  [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hwnd,int command);
  [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr hwnd);
  [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
  [DllImport("user32.dll")] static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
  [DllImport("user32.dll")] static extern bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo info);
  [StructLayout(LayoutKind.Sequential)] struct NativePoint { public int X, Y; }
  [StructLayout(LayoutKind.Sequential)] struct NativeRect { public int Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential)] struct MonitorInfo { public int Size; public NativeRect Monitor, Work; public uint Flags; }
  [StructLayout(LayoutKind.Sequential)] struct MinMaxInfo { public NativePoint Reserved, MaxSize, MaxPosition, MinTrackSize, MaxTrackSize; }

  // WM_GETMINMAXINFO uses physical pixels; do not mix these with WPF device-independent units.
  // https://learn.microsoft.com/windows/win32/api/winuser/ns-winuser-monitorinfo
  IntPtr WindowBoundsHook(IntPtr hwnd, int message, IntPtr wparam, IntPtr lparam, ref bool handled) {
   if (message != 0x0024) return IntPtr.Zero;
   var monitor = new MonitorInfo { Size = Marshal.SizeOf(typeof(MonitorInfo)) };
   if (!GetMonitorInfo(MonitorFromWindow(hwnd,2),ref monitor)) return IntPtr.Zero;
   var bounds = (MinMaxInfo)Marshal.PtrToStructure(lparam,typeof(MinMaxInfo));
   bounds.MaxPosition.X = monitor.Work.Left - monitor.Monitor.Left;
   bounds.MaxPosition.Y = monitor.Work.Top - monitor.Monitor.Top;
   bounds.MaxSize.X = monitor.Work.Right - monitor.Work.Left;
   bounds.MaxSize.Y = monitor.Work.Bottom - monitor.Work.Top;
   var source = HwndSource.FromHwnd(hwnd);
   var transform = source.CompositionTarget.TransformToDevice;
   bounds.MinTrackSize.X = Math.Min(bounds.MaxSize.X,(int)Math.Ceiling(MinWidth * transform.M11));
   bounds.MinTrackSize.Y = Math.Min(bounds.MaxSize.Y,(int)Math.Ceiling(MinHeight * transform.M22));
   Marshal.StructureToPtr(bounds,lparam,false);
   handled = true;
   return IntPtr.Zero;
  }

  public WebShell(bool smokeMode, bool connected, string fixture, bool workerTest, bool crashTest = false, bool rendererTest = false, bool browserTest = false) {
   integrationWorker = workerTest;
   integrationCrash = crashTest;
   integrationRenderer = rendererTest;
   integrationBrowser = browserTest;
   smoke = smokeMode; connectedSmoke = connected; testProfile = fixture;
   string bundled = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "portable.json");
   root = File.Exists(bundled) ? AppDomain.CurrentDomain.BaseDirectory : Environment.GetEnvironmentVariable("YUKIWIRE_ROOT");
   if (String.IsNullOrEmpty(root)) root = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ".."));
   root = Path.GetFullPath(root);
   dataRoot = File.Exists(bundled) ? root : Path.Combine(root,"runtime");
   Title = "Yukiwire"; MinWidth = Math.Min(800,SystemParameters.WorkArea.Width); MinHeight = Math.Min(620,SystemParameters.WorkArea.Height);
   Width = Math.Min(1120,SystemParameters.WorkArea.Width - 24); Height = Math.Min(760,SystemParameters.WorkArea.Height - 24);
   WindowStartupLocation = WindowStartupLocation.CenterScreen;
   // Capture the real renderer without covering or activating the user's desktop.
   if (smoke) { WindowStartupLocation = WindowStartupLocation.Manual; Left = -10000; Top = -10000; ShowInTaskbar = false; ShowActivated = false; }
   WindowStyle = WindowStyle.None; ResizeMode = ResizeMode.CanResize;
   Background = new SolidColorBrush(Color.FromRgb(32,33,34));
   WindowChrome.SetWindowChrome(this,new WindowChrome { CaptionHeight = 0, ResizeBorderThickness = new Thickness(6), CornerRadius = new CornerRadius(0), GlassFrameThickness = new Thickness(0), UseAeroCaptionButtons = false });
   view.DefaultBackgroundColor = System.Drawing.Color.FromArgb(255,32,33,34);
   Content = view;
   SourceInitialized += delegate { HwndSource.FromHwnd(new WindowInteropHelper(this).Handle).AddHook(WindowBoundsHook); };
   StateChanged += delegate {
    WindowChrome.GetWindowChrome(this).ResizeBorderThickness = new Thickness(WindowState == WindowState.Maximized ? 0 : 6);
    Post(new { @event = "window_state", maximized = WindowState == WindowState.Maximized });
   };
   string iconPath = Path.Combine(root,"ui","assets","yukiwire.ico");
   if (File.Exists(iconPath)) {
    // Preserve ICO frames so WPF chooses a full-size taskbar icon at each display scale.
    Icon = System.Windows.Media.Imaging.BitmapFrame.Create(new Uri(iconPath),
     System.Windows.Media.Imaging.BitmapCreateOptions.None, System.Windows.Media.Imaging.BitmapCacheOption.OnLoad);
    tray = new System.Windows.Forms.NotifyIcon { Icon = new System.Drawing.Icon(iconPath), Text = "Yukiwire · Запуск", Visible = !smoke };
    var menu = new System.Windows.Forms.ContextMenuStrip();
    menu.Items.Add("Открыть Yukiwire",null,delegate { RestoreWindow(); });
    trayConnect = new System.Windows.Forms.ToolStripMenuItem("Подключиться") { Enabled = false };
    trayConnect.Click += async delegate { if (uiReady && !closing) await view.CoreWebView2.ExecuteScriptAsync("document.getElementById('connect-button').click()"); };
    menu.Items.Add(trayConnect); menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
    menu.Items.Add("Выход",null,delegate { Close(); });
    tray.ContextMenuStrip = menu; tray.DoubleClick += delegate { RestoreWindow(); };
   }
   Loaded += async delegate { await Initialize(); };
   if (testProfile != null) {
    integrationTimeout = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(45) };
    integrationTimeout.Tick += delegate { integrationTimeout.Stop(); if (!closing) FinishIntegration(false,"timeout"); };
    integrationTimeout.Start();
   }
   Closing += delegate { PrepareShutdown(); if (tray != null) { tray.Visible = false; tray.Dispose(); } view.Dispose(); };
  }
  async Task Initialize() {
   try {
    int dark = 1; DwmSetWindowAttribute(new WindowInteropHelper(this).Handle,20,ref dark,4);
    // Never run a browser renderer with an explicitly disabled sandbox.
    var environment = await CoreWebView2Environment.CreateAsync(null, Path.Combine(dataRoot, smoke ? "ui-smoke-cache-" + Process.GetCurrentProcess().Id : testProfile != null ? "ui-test-cache" : "ui-cache"));
    await view.EnsureCoreWebView2Async(environment);
    var core = view.CoreWebView2;
    try {
     if (browserProcess != null) browserProcess.Dispose();
     browserProcess = Process.GetProcessById((int)core.BrowserProcessId); IntPtr boundBrowserHandle = browserProcess.Handle;
    } catch (Exception) { browserProcess = null; }
    core.Settings.AreDevToolsEnabled = false; core.Settings.AreDefaultContextMenusEnabled = false;
    core.Settings.AreHostObjectsAllowed = false; core.Settings.IsStatusBarEnabled = false;
    core.Settings.IsZoomControlEnabled = false;
    core.SetVirtualHostNameToFolderMapping("yukiwire.local",Path.Combine(root,"ui"),CoreWebView2HostResourceAccessKind.DenyCors);
    core.NavigationStarting += delegate(object sender,CoreWebView2NavigationStartingEventArgs e) { if (!Trusted(e.Uri)) e.Cancel = true; };
    core.NewWindowRequested += delegate(object sender,CoreWebView2NewWindowRequestedEventArgs e) { e.Handled = true; };
    core.PermissionRequested += delegate(object sender,CoreWebView2PermissionRequestedEventArgs e) { e.State = CoreWebView2PermissionState.Deny; };
    core.DownloadStarting += delegate(object sender,CoreWebView2DownloadStartingEventArgs e) { e.Cancel = true; };
    core.ProcessFailed += async delegate(object sender, CoreWebView2ProcessFailedEventArgs e) {
     if (e.ProcessFailedKind != CoreWebView2ProcessFailedKind.BrowserProcessExited && e.ProcessFailedKind != CoreWebView2ProcessFailedKind.RenderProcessExited) return;
     if (closing || recoveringRenderer) return;
     recoveringRenderer = true; uiReady = false;
     // The renderer owns no network state. Its replacement attaches to the same service/core.
     try {
      view.Dispose(); view = new WebView2 { DefaultBackgroundColor = System.Drawing.Color.FromArgb(255,32,33,34) }; Content = view;
      await Initialize();
     } finally { recoveringRenderer = false; }
    };
    core.WebMessageReceived += Receive;
    core.Navigate(Origin + "index.html");
    string oldError = Path.Combine(dataRoot,"ui-error.txt");
    if (File.Exists(oldError)) File.Delete(oldError);
   } catch (Exception e) {
    if (closing) return;
    File.WriteAllText(Path.Combine(dataRoot,"ui-error.txt"),e.GetType().Name + ": " + e.Message);
    var fallback = new StackPanel { Margin = new Thickness(60), VerticalAlignment = VerticalAlignment.Center };
    fallback.Children.Add(new TextBlock { Text = "Yukiwire", Foreground = Brushes.White, FontSize = 28, Margin = new Thickness(0,0,0,20) });
    fallback.Children.Add(new TextBlock { Text = "Не удалось открыть интерфейс. Проверьте Microsoft Edge WebView2 Runtime.\nПодробности сохранены в ui-error.txt.", Foreground = Brushes.LightGray, FontSize = 14, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,0,0,24) });
    var install = new Button { Content = "Открыть страницу WebView2", Padding = new Thickness(20,12,20,12), HorizontalAlignment = HorizontalAlignment.Left };
    install.Click += delegate { Process.Start(new ProcessStartInfo("https://developer.microsoft.com/en-us/microsoft-edge/webview2/#download-section") { UseShellExecute = true }); };
    var exit = new Button { Content = "Закрыть", Padding = new Thickness(20,12,20,12), Margin = new Thickness(0,12,0,0), HorizontalAlignment = HorizontalAlignment.Left };
    exit.Click += delegate { Close(); }; fallback.Children.Add(install); fallback.Children.Add(exit); Content = fallback;
    if (smoke || testProfile != null) { Environment.ExitCode = 1; Close(); }
   }
  }
  static bool Trusted(string value) {
   Uri uri; return Uri.TryCreate(value,UriKind.Absolute,out uri) && uri.Scheme == "https" && uri.Host == "yukiwire.local" && uri.IsDefaultPort && uri.AbsolutePath == "/index.html";
  }
  async void Receive(object sender, CoreWebView2WebMessageReceivedEventArgs e) {
   if (closing || !Trusted(e.Source)) return;
   try {
    var message = json.Deserialize<Dictionary<string,object>>(e.WebMessageAsJson);
    if (message == null || !message.ContainsKey("action")) return;
    string action = Convert.ToString(message["action"]);
    if (action == "ui_ready") {
     if (uiReady) return; uiReady = true;
     Post(new { @event = "window_state", maximized = WindowState == WindowState.Maximized });
     if (smoke) { await Smoke(); return; }
     if (backendStarted) Send(new { action = "get_state" }); else StartBackend(); return;
    }
    if (action == "window_close") { Close(); return; }
    if (action == "window_minimize") { WindowState = WindowState.Minimized; return; }
    if (action == "window_maximize") { WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized; return; }
    if (action == "window_drag") { ReleaseCapture(); SendMessage(new WindowInteropHelper(this).Handle,0xA1,new IntPtr(2),IntPtr.Zero); return; }
    if (action == "import_file") {
     var dialog = new OpenFileDialog { Filter = "Профили (*.json;*.txt)|*.json;*.txt", CheckFileExists = true };
     if (dialog.ShowDialog(this) == true) {
      var file = new FileInfo(dialog.FileName);
      if (file.Length > 1024 * 1024) throw new InvalidOperationException("Файл профиля больше 1 МБ.");
      Post(new { @event = "file_import", text = File.ReadAllText(dialog.FileName,Encoding.UTF8) });
     } return;
    }
    if (!actions.Contains(action)) return;
    if (testProfile != null && action == "start") {
     if (testProfile != "__SAVED_PROFILE__") message = new Dictionary<string,object> { {"action","start"}, {"profile",testProfile} };
     message["settings"] = new Dictionary<string,object> { {"capture","local"}, {"preset","all"} };
    }
    if (action == "stop" && workerPending != null) {
     workerGeneration++; workerPending = null;
     switchingBackend = true; StopBackend(); switchingBackend = false;
     backendStarted = false; StartBackend(); Post(new { @event = "stopped" }); return;
    }
    object captureValue = null;
    if (action == "start" && message.ContainsKey("settings")) {
     var settings = message["settings"] as Dictionary<string,object>;
     if (settings != null) settings.TryGetValue("capture",out captureValue);
    }
    bool administrator = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    if (action == "start" && workerInput == null && (!administrator && Convert.ToString(captureValue) == "tun" || integrationWorker)) {
     await StartNetworkWorker(message,!integrationWorker); return;
    }
    Send(message);
   } catch (Exception ex) { Post(new { @event = "error", operation = "host", message = ex is InvalidOperationException ? ex.Message : "Не удалось выполнить операцию интерфейса." }); }
  }
  void Post(object message) { PostJson(json.Serialize(message)); }
  void PostJson(string line) {
   if (closing || !uiReady || view.CoreWebView2 == null || !Trusted(view.CoreWebView2.Source)) return;
   view.CoreWebView2.PostWebMessageAsJson(line);
   if (tray != null) {
    try {
     var data = json.Deserialize<Dictionary<string,object>>(line);
     string kind = Convert.ToString(data["event"]);
     if (kind == "ready" || kind == "stopped") { tray.Text = "Yukiwire · Отключено"; trayConnect.Text = "Подключиться"; trayConnect.Enabled = true; }
     if (kind == "starting") { tray.Text = "Yukiwire · Подключение"; trayConnect.Text = "Отменить"; }
     if (kind == "started" || kind == "reconnecting") { tray.Text = "Yukiwire · Проверяем связь"; trayConnect.Text = "Отключить"; }
     if (kind == "probe_result") tray.Text = "Yukiwire · HTTPS работает";
     if (kind == "service_exited") { tray.Text = "Yukiwire · Сервис завершился"; trayConnect.Enabled = false; }
    } catch (Exception) { }
   }
  }
  void RestoreWindow() { Show(); if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal; Activate(); }
  void Send(object command) {
   if (workerInput != null) { workerInput.WriteLine(json.Serialize(command)); workerInput.Flush(); return; }
   if (backend == null || backend.HasExited) throw new InvalidOperationException("Сервис ещё не готов.");
   backend.StandardInput.WriteLine(json.Serialize(command)); backend.StandardInput.Flush();
  }
  async Task OpenProxyBrowser() {
   if (closing || launchingBrowser) return;
   launchingBrowser = true;
   try {
    string bundled = Path.Combine(root,"python","python.exe");
    string python = File.Exists(bundled) ? bundled : Environment.GetEnvironmentVariable("YUKIWIRE_PYTHON");
    string response = await Task.Run(delegate {
     // Inherit the UI token, never the elevated TUN worker's token.
     var start = new ProcessStartInfo(python,"-B -u \"" + Path.Combine(root,"scripts","worker.py") + "\" --worker yukiwire.browser") {
      WorkingDirectory = root, UseShellExecute = false, CreateNoWindow = true,
      RedirectStandardOutput = true, RedirectStandardError = true,
      StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
     };
     start.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8";
     using (var process = new Process { StartInfo = start }) {
      process.Start(); process.ErrorDataReceived += delegate { }; process.BeginErrorReadLine();
      var output = process.StandardOutput.ReadToEndAsync();
      if (!process.WaitForExit(5000)) { process.Kill(); throw new InvalidOperationException(); }
      if (process.ExitCode != 0) throw new InvalidOperationException();
      return output.GetAwaiter().GetResult();
     }
    });
    var message = json.Deserialize<Dictionary<string,object>>(response);
    string kind = Convert.ToString(message["event"]);
    if (kind != "browser_opened" && kind != "error") throw new InvalidOperationException();
    Post(message);
   } catch (Exception) { Post(new { @event = "error", operation = "open_browser", message = "Не удалось открыть браузер с прокси Yukiwire." }); }
   finally { launchingBrowser = false; }
  }
  void StartBackend() {
   if (backendStarted) return; backendStarted = true;
   try {
    string bundledPython = Path.Combine(root,"python","python.exe");
    string python = File.Exists(bundledPython) ? bundledPython : Environment.GetEnvironmentVariable("YUKIWIRE_PYTHON");
    if (String.IsNullOrEmpty(python)) throw new InvalidOperationException("Не найден Python для запуска из исходников.");
    string args = "-B -u \"" + Path.Combine(root,"scripts","worker.py") + "\" --worker yukiwire.backend";
    backend = new Process { StartInfo = new ProcessStartInfo(python,args) { WorkingDirectory = root, UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 }, EnableRaisingEvents = true };
    backend.StartInfo.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8";
    backend.StartInfo.EnvironmentVariables["PYTHON_DISABLE_REMOTE_DEBUG"] = "1";
    backend.StartInfo.EnvironmentVariables["YUKIWIRE_TEST_SESSION"] = testProfile != null || smoke ? "1" : "0";
    Process currentBackend = backend;
    backend.OutputDataReceived += delegate(object sender,DataReceivedEventArgs e) {
     if (e.Data == null || closing || backend != currentBackend) return;
     Dispatcher.BeginInvoke(new Action(async delegate {
      if (closing || backend != currentBackend) return;
      try {
       var message = json.Deserialize<Dictionary<string,object>>(e.Data);
       if (Convert.ToString(message["event"]) == "browser_requested") { await OpenProxyBrowser(); return; }
       if (Convert.ToString(message["event"]) == "recovery_elevation_required") {
        await StartNetworkWorker(new { action = "recover_network" },true); return;
       }
       PostJson(e.Data); if (testProfile != null) Integration(message);
      }
      catch (Exception) { Post(new { @event = "error", operation = "host", message = "Не удалось прочитать ответ сервиса." }); }
     }));
    };
    // Raw backend output can contain private details. Do not relay stderr to the UI or logs.
    backend.ErrorDataReceived += delegate { };
    backend.Exited += delegate { if (!closing && !switchingBackend) Dispatcher.BeginInvoke(new Action(delegate { if (backend == currentBackend && !switchingBackend) Post(new { @event = "service_exited" }); })); };
    backend.Start(); backend.BeginOutputReadLine(); backend.BeginErrorReadLine();
   } catch (Exception) { Post(new { @event = "error", operation = "host", message = "Не удалось запустить сетевой сервис." }); if (testProfile != null) FinishIntegration(false,"backend_failed"); }
  }
  async Task StartNetworkWorker(object request,bool elevate) {
   int generation = ++workerGeneration;
   switchingBackend = true; StopBackend(); switchingBackend = false;
   workerPending = request;
   string name = "Yukiwire." + Guid.NewGuid().ToString("N");
   var security = new PipeSecurity(); security.SetAccessRuleProtection(true,false);
   security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid,null),PipeAccessRights.FullControl,AccessControlType.Deny));
   security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User,PipeAccessRights.FullControl,AccessControlType.Allow));
   var pipe = new NamedPipeServerStream(name,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,4096,4096,security);
   workerPipe = pipe;
   try {
    var wait = Task.Factory.FromAsync(pipe.BeginWaitForConnection,pipe.EndWaitForConnection,null);
    string bundled = Path.Combine(root,"python","python.exe");
    string python = File.Exists(bundled) ? bundled : Environment.GetEnvironmentVariable("YUKIWIRE_PYTHON");
    string args = "--network-worker " + name + " " + Process.GetCurrentProcess().Id + " " + Process.GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc() + " \"" + python + "\"" + (testProfile != null ? " --test-session" : "");
    var worker = await Task.Run(delegate { return Process.Start(new ProcessStartInfo(System.Reflection.Assembly.GetExecutingAssembly().Location,args) { UseShellExecute = true, Verb = elevate ? "runas" : "", WindowStyle = ProcessWindowStyle.Hidden, WorkingDirectory = root }); });
    if (closing || generation != workerGeneration) { pipe.Dispose(); return; }
    networkWorker = worker;
    if (await Task.WhenAny(wait,Task.Delay(90000)) != wait) throw new InvalidOperationException("Сетевой помощник не запустился.");
    await wait;
    uint client;
    if (networkWorker == null || !NetworkWorker.GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(),out client) || client != networkWorker.Id) throw new InvalidOperationException("Не удалось проверить сетевой помощник.");
    if (closing || generation != workerGeneration) { pipe.Dispose(); return; }
    workerInput = new StreamWriter(pipe,new UTF8Encoding(false),4096,true) { AutoFlush = true };
    var reader = new StreamReader(pipe,Encoding.UTF8,false,4096,true);
    workerReader = Task.Run(delegate {
     try {
      string line;
      while ((line = reader.ReadLine()) != null) {
       string captured = line;
       Dispatcher.BeginInvoke(new Action(async delegate {
        if (closing || generation != workerGeneration) return;
        try {
         var data = json.Deserialize<Dictionary<string,object>>(captured);
         if (Convert.ToString(data["event"]) == "browser_requested") { await OpenProxyBrowser(); return; }
         PostJson(captured);
         if (Convert.ToString(data["event"]) == "ready" && workerPending != null) { var pending = workerPending; workerPending = null; Send(pending); }
         if (testProfile != null) Integration(data);
        } catch (Exception) { Post(new { @event = "error", operation = "host", message = "Ошибка связи с сетевым помощником." }); }
       }));
      }
     } catch (Exception) { }
     finally { if (!closing) Dispatcher.BeginInvoke(new Action(delegate { if (generation == workerGeneration) { workerInput = null; Post(new { @event = "service_exited" }); } })); }
    });
   } catch (Exception) {
    pipe.Dispose();
    if (!closing && generation == workerGeneration) {
     workerInput = null; workerPending = null;
     Post(new { @event = "error", operation = "start", message = "Для TUN подтвердите запуск сетевого помощника в окне Windows. Настройки сети не изменены." });
     backendStarted = false; StartBackend();
    }
   }
  }
  void StopBackend() {
   if (workerPipe != null) {
    try { if (workerInput != null) { workerInput.WriteLine(json.Serialize(new { action = "quit" })); workerInput.Flush(); } } catch (Exception) { }
    try { workerPipe.Dispose(); } catch (Exception) { }
    workerPipe = null; workerInput = null;
    try { if (networkWorker != null) networkWorker.WaitForExit(5500); } catch (Exception) { }
    networkWorker = null;
   }
   if (backend == null) return;
   try {
    if (!backend.HasExited) { try { Send(new { action = "quit" }); backend.StandardInput.Close(); } catch (Exception) { }
     if (!backend.WaitForExit(3500)) { backend.Kill(); backend.WaitForExit(1500); }
    }
   } catch (Exception) { }
   backend = null;
  }
  public void PrepareShutdown() { if (closing) return; closing = true; if (integrationTimeout != null) integrationTimeout.Stop(); StopBackend(); }
  void WaitForBrowserExit() { try { if (browserProcess != null) { browserProcess.WaitForExit(6000); browserProcess.Dispose(); } } catch (Exception) { } }
  async void Integration(Dictionary<string,object> data) {
   string kind = Convert.ToString(data["event"]); integrationEvents.Add(kind);
   if (kind == "ready" && integrationPhase == 0) {
    integrationPhase = 1;
    if (testProfile != "__SAVED_PROFILE__") Post(new { @event = "profiles", profiles = new[] { new { id = "fixture", name = "Тестовый профиль", protocol = "vless" } }, selected = "fixture" });
    await Task.Delay(100);
    if (!closing) await view.CoreWebView2.ExecuteScriptAsync("document.getElementById('connect-button').click()");
   } else if (kind == "started" && integrationPhase == 1) {
    integrationPhase = 2;
    originalCorePid = Convert.ToInt32(data["pid"]);
    if (integrationCrash) File.WriteAllText(Path.Combine(dataRoot,"native-crash-ready.json"),json.Serialize(new { host_pid = Process.GetCurrentProcess().Id, worker_pid = networkWorker.Id, core_pid = data["pid"] }));
   }
   else if ((kind == "probe_result" || kind == "error") && integrationPhase == 2) {
    if (integrationCrash) return;
    if (integrationRenderer && kind == "probe_result") {
     integrationNetwork = true; integrationPhase = 4;
     // Deliberately crash only this test renderer, through the host's private API.
     if (integrationBrowser) browserProcess.Kill();
     else { try { await view.CoreWebView2.CallDevToolsProtocolMethodAsync("Page.crash","{}"); } catch (Exception) { } }
     return;
    }
    integrationNetwork = kind == "probe_result"; integrationPhase = 3;
    await view.CoreWebView2.ExecuteScriptAsync("document.getElementById('connect-button').click()");
   } else if (kind == "started" && integrationPhase == 4) {
    rendererRecovered = Convert.ToInt32(data["pid"]) == originalCorePid;
    if (!rendererRecovered) { FinishIntegration(false,"core_restarted_with_renderer"); return; }
    integrationPhase = 5;
   } else if (kind == "probe_result" && integrationPhase == 5) {
    integrationPhase = 3;
    // Snapshot messages are posted as one batch; wait until the restored UI has consumed them.
    await view.CoreWebView2.ExecuteScriptAsync("(function(){const until=Date.now()+5000;function stop(){const b=document.getElementById('connect-button');if(b && !b.disabled && b.querySelector('span').textContent==='Отключить'){b.click();return;}if(Date.now()<until)setTimeout(stop,20);}stop();})()");
   } else if (kind == "stopped" && integrationPhase == 3) FinishIntegration(true,"completed");
   else if (kind == "error" && integrationPhase == 1) FinishIntegration(false,"start_failed");
  }
  void FinishIntegration(bool passed,string reason) {
   if (closing) return;
   File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"native-integration-report.json"),json.Serialize(new { lifecycle_passed = passed, network_response_received = integrationNetwork, renderer_recovered_without_core_restart = rendererRecovered, reason = reason, events = integrationEvents }));
   Environment.ExitCode = passed ? 0 : 1; Close();
  }
  async Task Smoke() {
   Post(new { @event = "ready", profiles = new[] { new { id = "preview", name = "Домашний сервер", protocol = "vless" } }, selected = "preview", settings = new { capture = "local", preset = "ru-direct" }, environment = new { other_proxy = true, other_vpn = true } });
   if (connectedSmoke) {
    Post(new { @event = "started", capture = "local" }); Post(new { @event = "probe_result", elapsed_ms = 184 });
    Post(new { @event = "telemetry", download_bytes = 138127493, upload_bytes = 13501324, download_bps = 780932, upload_bps = 42342, uptime = 924, reconnects = 0, direct_bytes = 501223 });
   }
   await Task.Delay(1200);
   foreach (string page in new[] { "home","profiles","routing","settings","activity" }) {
    if (page != "home") await view.CoreWebView2.ExecuteScriptAsync("window.yukiwire.openPanel('" + page + "')");
    await Task.Delay(350);
    using (var stream = File.Create(Path.Combine(dataRoot,(connectedSmoke ? "ui-connected-" : "ui-") + page + ".png"))) await view.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png,stream);
    await view.CoreWebView2.ExecuteScriptAsync("window.yukiwire.closePanel()");
   } Close();
  }
  [STAThread] public static int Main(string[] args) {
   if (args.Length > 0 && args[0] == "--network-worker") return NetworkWorker.Run(args);
   bool smokeMode = args.Length > 0 && (args[0] == "--smoke" || args[0] == "--smoke-connected");
   bool created;
   string mutexName = "Local\\Yukiwire.NativeShell" + (smokeMode ? ".Smoke." + Process.GetCurrentProcess().Id : "");
   using (var instance = new Mutex(true,mutexName,out created)) {
    if (!created) { IntPtr existing = FindWindow(null,"Yukiwire"); if (existing != IntPtr.Zero) { ShowWindow(existing,9); SetForegroundWindow(existing); } return 0; }
    bool connected = args.Length > 0 && args[0] == "--smoke-connected";
    bool crashTest = args.Length > 0 && args[0] == "--integration-worker-crash";
    string fixture = args.Length > 1 && (args[0] == "--integration" || args[0] == "--integration-worker" || crashTest) ? File.ReadAllText(args[1],Encoding.UTF8) : null;
    bool browserTest = args.Length > 0 && args[0] == "--integration-browser-saved";
    bool rendererTest = args.Length > 0 && args[0] == "--integration-renderer-saved" || browserTest;
    if (args.Length > 0 && (args[0] == "--integration-saved" || args[0] == "--integration-worker-saved" || rendererTest)) fixture = "__SAVED_PROFILE__";
    var app = new Application(); var shell = new WebShell(smokeMode,connected,fixture,crashTest || args.Length > 0 && (args[0] == "--integration-worker" || args[0] == "--integration-worker-saved"),crashTest,rendererTest,browserTest);
    app.SessionEnding += delegate { shell.PrepareShutdown(); };
    app.Run(shell); shell.WaitForBrowserExit(); return Environment.ExitCode;
   }
  }
 }
}
