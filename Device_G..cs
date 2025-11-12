// that's not just copy and past u should to change some data in some lines 

// Single-file defensive device monitor (C# .NET 6+)

// Save as Device_G.cs and run under dotnet .

// Features:
//  - Process monitor (detects new processes, suspicious paths)
//  - Network monitor (active TCP connections, listening ports, outbound spikes)
//  - Service monitor (new/changed Windows services)
//  - Auto-start monitor (Registry run keys + Startup folders)
//  - File-system monitor for critical directories (new/changed .exe/.dll)
//  - Logging and simple alert webhook support
//
// Run as Administrator for best detection coverage.
// Tune thresholds and suspicious lists below as needed.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

class DeviceGuardian
{
    //  Configuration 
    static readonly TimeSpan POLL_INTERVAL = TimeSpan.FromSeconds(5);    // main loop tick
    static readonly TimeSpan STATS_INTERVAL = TimeSpan.FromSeconds(30); // summary print
    static readonly int OUTBOUND_CONN_SPIKE_THRESHOLD = 30; // new outbound conns in window -> alert
    static readonly TimeSpan OUTBOUND_CONN_WINDOW = TimeSpan.FromSeconds(20);

    // directories watched for new/modified executables
    static readonly string[] WATCH_DIRS = new string[] {
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData\\Local"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData\\Roaming")
    };

    // registry Run keys to check
    static readonly (RegistryHive hive, string subKey)[] RUN_REG_KEYS = new (RegistryHive, string)[] {
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run")
    };

    // example suspicious process name substrings (tune to your environment)
    static readonly string[] SUSPICIOUS_PROCESS_SUBSTRINGS = new string[] {
        "netcat", "nc.exe", "ncat", "psexec", "mimikatz", "rundll32", "wmic", "powershell", "psexec",
        "meterpreter", "reverse", "cmd.exe" // note: cmd.exe & powershell are common - you'll get false positives
    };

    // webhook to send alerts (optional). Leave null to disable.
    static readonly string ALERT_WEBHOOK_URL = null; // e.g. "https://example.com/alert"

    // log file
    static readonly string LOG_FILE = Path.Combine(AppContext.BaseDirectory, "DeviceGuardian.log");

    //  State 
    static readonly object logLock = new object();
    static HashSet<int> knownPids = new HashSet<int>();
    static HashSet<string> knownFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    static Dictionary<IPAddress, List<DateTime>> outboundConnHistory = new Dictionary<IPAddress, List<DateTime>>();
    static HashSet<int> knownListeningPorts = new HashSet<int>();
    static HashSet<string> knownServiceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    static HashSet<string> knownStartupEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    static HttpClient httpClient = new HttpClient() { Timeout = TimeSpan.FromSeconds(5) };

    static void Main(string[] args)
    {
        PrintHeader();

        // require admin for some checks
        if (!IsAdministrator())
        {
            Log("[WARN] Not running as Administrator — monitoring coverage reduced. Run as admin for full features.");
        }

        // init known state
        InitKnownProcesses();
        InitKnownFiles();
        InitKnownListeningPorts();
        InitKnownServices();
        InitKnownStartupEntries();

        // setup file system watchers
        foreach (var dir in WATCH_DIRS)
        {
            try
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                SetupDirectoryWatcher(dir);
            }
            catch (Exception ex)
            {
                Log($"[WARN] Failed to set watcher on {dir}: {ex.Message}");
            }
        }

        // main monitoring loops
        CancellationTokenSource cts = new CancellationTokenSource();
        Task.Run(() => StatsPrinter(cts.Token));
        Task.Run(() => PeriodicServiceAndStartupCheck(cts.Token));

        // primary polling loop
        while (true)
        {
            try
            {
                MonitorProcesses();
                MonitorNetwork();
                MonitorListeningPorts();
                Thread.Sleep(POLL_INTERVAL);
            }
            catch (Exception ex)
            {
                Log("[ERROR] Main loop exception: " + ex.ToString());
            }
        }
    }

    static void PrintHeader()
    {
        Console.WriteLine("=== DeviceGuardian - Continuous Device Monitor ===");
        Console.WriteLine($"Started at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine("Run as admin for better detection. Press Ctrl+C to exit.");
        Console.WriteLine();
        Log("DeviceGuardian started.");
    }

    // Initialization helpers 
    static void InitKnownProcesses()
    {
        try
        {
            var procs = Process.GetProcesses();
            lock (knownPids)
            {
                knownPids = new HashSet<int>(procs.Select(p => p.Id));
            }
            Log($"Initialized processes snapshot: {knownPids.Count} processes.");
        }
        catch (Exception ex)
        {
            Log("[WARN] Could not enumerate processes: " + ex.Message);
        }
    }

    static void InitKnownFiles()
    {
        try
        {
            foreach (var d in WATCH_DIRS)
            {
                if (string.IsNullOrEmpty(d) || !Directory.Exists(d)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(d, "*.*", SearchOption.AllDirectories))
                    {
                        if (IsBinaryFilePath(f))
                        {
                            knownFiles.Add(f);
                        }
                    }
                }
                catch { /* skip subtrees we can't access */ }
            }
            Log($"Initialized file snapshot: {knownFiles.Count} binaries tracked.");
        }
        catch (Exception ex)
        {
            Log("[WARN] InitKnownFiles failed: " + ex.Message);
        }
    }

    static void InitKnownListeningPorts()
    {
        try
        {
            var ports = GetListeningTcpPorts();
            knownListeningPorts = new HashSet<int>(ports);
            Log($"Initialized listening ports: {knownListeningPorts.Count}");
        }
        catch (Exception ex)
        {
            Log("[WARN] InitKnownListeningPorts failed: " + ex.Message);
        }
    }

    static void InitKnownServices()
    {
        try
        {
            var services = ServiceController.GetServices();
            knownServiceNames = new HashSet<string>(services.Select(s => s.ServiceName), StringComparer.OrdinalIgnoreCase);
            Log($"Initialized services snapshot: {knownServiceNames.Count}");
        }
        catch (Exception ex)
        {
            Log("[WARN] InitKnownServices failed: " + ex.Message);
        }
    }

    static void InitKnownStartupEntries()
    {
        try
        {
            foreach (var kv in RUN_REG_KEYS)
            {
                try
                {
                    using RegistryKey root = RegistryKey.OpenBaseKey(kv.hive, RegistryView.Registry64);
                    using RegistryKey runKey = root.OpenSubKey(kv.subKey, false);
                    if (runKey == null) continue;
                    foreach (var name in runKey.GetValueNames())
                    {
                        var v = runKey.GetValue(name)?.ToString() ?? "";
                        knownStartupEntries.Add($"{name}|{v}");
                    }
                }
                catch { }
            }

            var userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            foreach (var f in new[] { userStartup, commonStartup })
            {
                if (Directory.Exists(f))
                {
                    foreach (var item in Directory.EnumerateFileSystemEntries(f))
                        knownStartupEntries.Add(item);
                }
            }
            Log($"Initialized startup entries: {knownStartupEntries.Count}");
        }
        catch (Exception ex)
        {
            Log("[WARN] InitKnownStartupEntries failed: " + ex.Message);
        }
    }

    // Monitoring components 

    // Processes: detect new processes, suspicious paths, terminated processes
    static void MonitorProcesses()
    {
        try
        {
            var current = Process.GetProcesses();
            var currentIds = new HashSet<int>(current.Select(p => p.Id));

            // new processes
            List<Process> newProcs = new List<Process>();
            lock (knownPids)
            {
                foreach (var p in current)
                {
                    if (!knownPids.Contains(p.Id))
                    {
                        newProcs.Add(p);
                    }
                }
                // update known
                knownPids = currentIds;
            }

            foreach (var p in newProcs)
            {
                try
                {
                    string path = SafeGetProcessPath(p);
                    string name = p.ProcessName;
                    Log($"[PROCESS] New PID={p.Id} Name={name} Path={path}");
                    // basic heuristics
                    if (IsSuspiciousProcessName(name) || IsSuspiciousPath(path))
                    {
                        string alert = $"[ALERT] Suspicious process: {name} (PID {p.Id}) Path={path}";
                        Alert(alert);
                    }
                }
                catch (Exception ex)
                {
                    Log("[WARN] Process inspection failed: " + ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            Log("[WARN] MonitorProcesses failed: " + ex.Message);
        }
    }

    // Network: detect many outbound connections and new remote IPs
    static void MonitorNetwork()
    {
        try
        {
            var connections = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
            var now = DateTime.UtcNow;

            foreach (var c in connections)
            {
                if (c.State != TcpState.Established) continue;
                var remote = c.RemoteEndPoint.Address;
                var local = c.LocalEndPoint.Address;
                // only outbound (remote not loopback and not local)
                if (remote.Equals(IPAddress.Loopback) || IPAddress.IsLoopback(remote)) continue;

                lock (outboundConnHistory)
                {
                    if (!outboundConnHistory.TryGetValue(remote, out var list))
                    {
                        list = new List<DateTime>();
                        outboundConnHistory[remote] = list;
                    }
                    list.Add(now);

                    // purge older entries
                    list.RemoveAll(t => t < now - OUTBOUND_CONN_WINDOW);

                    if (list.Count >= OUTBOUND_CONN_SPIKE_THRESHOLD)
                    {
                        Alert($"[ALERT] Outbound connection spike to {remote} : {list.Count} connections within {OUTBOUND_CONN_WINDOW.TotalSeconds}s");
                        list.Clear(); // reset after alert
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Log("[WARN] MonitorNetwork failed: " + ex.Message);
        }
    }

    // Monitor listening ports and alert on new ones
    static void MonitorListeningPorts()
    {
        try
        {
            var ports = GetListeningTcpPorts();
            var set = new HashSet<int>(ports);

            // detect newly opened listening ports
            foreach (var p in set)
            {
                if (!knownListeningPorts.Contains(p))
                {
                    knownListeningPorts.Add(p);
                    Log($"[PORT] New listening TCP port detected: {p}");
                    // alert only if port is not known common (e.g., 80,443,3389)
                    if (!IsCommonPort(p))
                    {
                        Alert($"[ALERT] New listening TCP port: {p}");
                    }
                }
            }

            // optional: detect closed ports (removed)
            var removed = knownListeningPorts.Where(p => !set.Contains(p)).ToList();
            foreach (var p in removed)
            {
                knownListeningPorts.Remove(p);
                Log($"[PORT] Listening TCP port closed: {p}");
            }
        }
        catch (Exception ex)
        {
            Log("[WARN] MonitorListeningPorts failed: " + ex.Message);
        }
    }

    // Periodic: services + startup entries
    static async Task PeriodicServiceAndStartupCheck(CancellationToken token)
    {
        while (true)
        {
            try
            {
                // services
                var services = ServiceController.GetServices();
                foreach (var s in services)
                {
                    if (!knownServiceNames.Contains(s.ServiceName))
                    {
                        knownServiceNames.Add(s.ServiceName);
                        Log($"[SERVICE] New service detected: {s.ServiceName} ({s.DisplayName})");
                        Alert($"[ALERT] New service installed: {s.ServiceName}");
                    }
                }

                // startup entries (registry Run keys + folders)
                foreach (var kv in RUN_REG_KEYS)
                {
                    try
                    {
                        using RegistryKey root = RegistryKey.OpenBaseKey(kv.hive, RegistryView.Registry64);
                        using RegistryKey runKey = root.OpenSubKey(kv.subKey, false);
                        if (runKey != null)
                        {
                            foreach (var name in runKey.GetValueNames())
                            {
                                var v = runKey.GetValue(name)?.ToString() ?? "";
                                string key = $"{name}|{v}";
                                if (!knownStartupEntries.Contains(key))
                                {
                                    knownStartupEntries.Add(key);
                                    Log($"[AUTO-START] New registry autostart: {name} -> {v}");
                                    Alert($"[ALERT] New autostart registry entry: {name}");
                                }
                            }
                        }
                    }
                    catch { }
                }

                // startup folders
                var userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
                foreach (var f in new[] { userStartup, commonStartup })
                {
                    try
                    {
                        if (!Directory.Exists(f)) continue;
                        foreach (var item in Directory.EnumerateFileSystemEntries(f))
                        {
                            if (!knownStartupEntries.Contains(item))
                            {
                                knownStartupEntries.Add(item);
                                Log($"[AUTO-START] New startup folder item: {item}");
                                Alert($"[ALERT] New startup item in startup folder: {Path.GetFileName(item)}");
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Log("[WARN] PeriodicServiceAndStartupCheck failed: " + ex.Message);
            }

            await Task.Delay(TimeSpan.FromSeconds(10), token).ContinueWith(_ => { });
        }
    }

    // File system watchers 

    static void SetupDirectoryWatcher(string dir)
    {
        try
        {
            var fsw = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = true,
                EnableRaisingEvents = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.Size
            };

            fsw.Created += (s, e) =>
            {
                try
                {
                    if (IsBinaryFilePath(e.FullPath))
                    {
                        if (!knownFiles.Contains(e.FullPath))
                        {
                            knownFiles.Add(e.FullPath);
                            Log($"[FS] New binary file: {e.FullPath}");
                            Alert($"[ALERT] New binary created: {e.FullPath}");
                        }
                    }
                }
                catch { }
            };

            fsw.Changed += (s, e) =>
            {
                try
                {
                    if (IsBinaryFilePath(e.FullPath))
                    {
                        Log($"[FS] Modified binary: {e.FullPath}");
                        // you could compute hash and compare to baseline here
                    }
                }
                catch { }
            };

            fsw.Renamed += (s, e) =>
            {
                try
                {
                    Log($"[FS] Renamed: {e.OldFullPath} -> {e.FullPath}");
                    if (IsBinaryFilePath(e.FullPath))
                    {
                        if (!knownFiles.Contains(e.FullPath))
                        {
                            knownFiles.Add(e.FullPath);
                            Alert($"[ALERT] New binary (renamed/created): {e.FullPath}");
                        }
                    }
                }
                catch { }
            };

            fsw.Deleted += (s, e) =>
            {
                try
                {
                    if (knownFiles.Contains(e.FullPath))
                    {
                        knownFiles.Remove(e.FullPath);
                        Log($"[FS] Deleted tracked binary: {e.FullPath}");
                    }
                }
                catch { }
            };

            Log($"[FS] Watching directory: {dir}");
        }
        catch (Exception ex)
        {
            Log($"[WARN] Could not create watcher for {dir}: {ex.Message}");
        }
    }

    //  Utility / heuristics 

    static bool IsBinaryFilePath(string path)
    {
        try
        {
            if (string.IsNullOrEmpty(path)) return false;
            string ext = Path.GetExtension(path).ToLowerInvariant();
            return ext == ".exe" || ext == ".dll" || ext == ".scr" || ext == ".bat" || ext == ".cmd" || ext == ".ps1";
        }
        catch { return false; }
    }

    static bool IsSuspiciousProcessName(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        var n = name.ToLowerInvariant();
        foreach (var s in SUSPICIOUS_PROCESS_SUBSTRINGS)
        {
            if (n.Contains(s)) return true;
        }
        return false;
    }

    static bool IsSuspiciousPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var lp = path.ToLowerInvariant();
        // suspicious if running from Temp or user profile temp locations
        if (lp.Contains("\\temp\\") || lp.Contains("\\appdata\\local\\temp") || lp.Contains("\\appdata\\roaming\\"))
            return true;
        // suspicious if path has odd characters or network paths
        if (lp.StartsWith("\\\\"))
            return true;
        return false;
    }

    static bool IsCommonPort(int port)
    {
        int[] common = new int[] { 20,21,22,23,25,53,80,110,143,443,3389,135,445,139 };
        return common.Contains(port);
    }

    // Safe get process path (may throw for protected processes)
    static string SafeGetProcessPath(Process p)
    {
        try
        {
            return p.MainModule?.FileName ?? "(no path)";
        }
        catch
        {
            // fallback via WMI or toolhelp could be added; keep simple
            return "(access denied or system process)";
        }
    }

    //  Alerting / logging 

    static void Log(string s)
    {
        var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {s}";
        lock (logLock)
        {
            Console.WriteLine(line);
            try
            {
                File.AppendAllText(LOG_FILE, line + Environment.NewLine);
            }
            catch { }
        }
    }

    static void Alert(string s)
    {
        Log(s);
        // optionally post to webhook
        if (!string.IsNullOrEmpty(ALERT_WEBHOOK_URL))
        {
            try
            {
                var payload = new StringContent("{\"alert\":\"" + EscapeForJson(s) + "\"}", Encoding.UTF8, "application/json");
                httpClient.PostAsync(ALERT_WEBHOOK_URL, payload).ContinueWith(t =>
                {
                    if (t.IsFaulted || !t.Result.IsSuccessStatusCode)
                    {
                        Log("[WARN] Failed to send webhook alert.");
                    }
                });
            }
            catch
            {
                Log("[WARN] Exception while sending webhook");
            }
        }

        // Optionally, show a simple Windows notification (requires additional packages).
    }

    static string EscapeForJson(string s)
    {
        return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }

    //  Stats printer 
    static void StatsPrinter(CancellationToken token)
    {
        while (true)
        {
            try
            {
                Thread.Sleep(STATS_INTERVAL);
                int procCount = 0;
                try { procCount = Process.GetProcesses().Length; } catch { }
                int trackedFiles = knownFiles.Count;
                int listening = knownListeningPorts.Count;
                int services = knownServiceNames.Count;
                Log($"[STATS] Processes={procCount} | Tracked files={trackedFiles} | ListeningPorts={listening} | Services={services}");
            }
            catch (ThreadInterruptedException) { break; }
            catch { }
            if (token.IsCancellationRequested) break;
        }
    }

    //  Network helpers 

    // Return currently listening TCP ports (local)
    static IEnumerable<int> GetListeningTcpPorts()
    {
        try
        {
            var ipProps = IPGlobalProperties.GetIPGlobalProperties();
            var listeners = ipProps.GetActiveTcpListeners();
            foreach (var ep in listeners)
                yield return ep.Port;
        }
        catch { yield break; }
    }

    //  Helpers 

    static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
