using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Threading;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Terraria;
using TerrariaApi.Server;
using TShockAPI;

namespace AntiCrawler
{
    public enum LogLevel
    {
        Debug = 0,   // every allowed connection, known-good marking
        Info = 1,    // drops, timeouts, ban expiry, commands
        Warning = 2, // strikes, concurrent-cap hits, forced resets
        Alert = 3    // bans, poisoned buffers
    }

    /// <summary>
    /// Protects a TShock server from port scanners / crawlers / fake connections that
    /// leave half-open slots behind and wedge the network layer.
    /// It also finds sockets that ServerConnect never reported, and clears
    /// "poisoned" receive buffers that would otherwise re-throw forever.
    /// </summary>
    [ApiVersion(2, 1)]
    public sealed class AntiCrawlerPlugin : TerrariaPlugin
    {
        public override string Name => "AntiCrawler";
        public override string Author => "red9350";
        public override string Description => "Drops scanners/crawlers and cleans stuck connection slots.";
        public override Version Version => new Version(1, 0, 0);

        private const string NotifyPermission = "anticrawler.notify";
        private const string AdminPermission = "anticrawler.admin";

        // ------------------------------------------------------------------ config

        public sealed class Config
        {
            // --- detection
            /// <summary>Seconds a fresh socket may stay in State 0 without a valid ConnectRequest.</summary>
            public int HandshakeTimeoutSeconds { get; set; } = 10;
            /// <summary>Seconds a client may spend in States 1-9 (password, world download) before being dropped.</summary>
            public int LoadingTimeoutSeconds { get; set; } = 180;
            /// <summary>Max simultaneous sockets from one IP (keep >1 for NAT / households).</summary>
            public int MaxConcurrentPerIp { get; set; } = 4;
            /// <summary>Sliding window for the connect rate limit.</summary>
            public int ConnectWindowSeconds { get; set; } = 30;
            /// <summary>More than this many connects inside the window = flood = ban.</summary>
            public int MaxConnectsPerWindow { get; set; } = 8;
            public int StrikesBeforeBan { get; set; } = 3;
            public int StrikeWindowMinutes { get; set; } = 10;
            /// <summary>First ban length; doubles on every repeat offence.</summary>
            public int InitialBanMinutes { get; set; } = 30;
            public int MaxBanMinutes { get; set; } = 1440;
            /// <summary>IPs that completed a real login are exempt from rate limits/strikes for this long.</summary>
            public int KnownGoodHours { get; set; } = 12;
            /// <summary>A receive buffer that stays flagged "needs parsing" with unchanged data this long is considered poisoned.</summary>
            public int StuckBufferSeconds { get; set; } = 3;
            public List<string> Whitelist { get; set; } = new List<string> { "127.0.0.1", "::1" };

            // --- logging
            /// <summary>Debug | Info | Warning | Alert. Set to Debug to also log every allowed connection.</summary>
            [JsonConverter(typeof(StringEnumConverter))]
            public LogLevel ConsoleMinLevel { get; set; } = LogLevel.Info;
            /// <summary>Send events to online players with the anticrawler.notify permission.</summary>
            public bool ChatEnabled { get; set; } = true;
            [JsonConverter(typeof(StringEnumConverter))]
            public LogLevel ChatMinLevel { get; set; } = LogLevel.Warning;
            /// <summary>Max chat lines per second per admin; the rest is summarised as "+N more".</summary>
            public int ChatMaxPerSecond { get; set; } = 5;
            /// <summary>Identical repeating events (e.g. a banned IP hammering you) are logged once per this many seconds.</summary>
            public int LogThrottleSeconds { get; set; } = 10;
        }

        private sealed class IpRecord
        {
            public readonly Queue<DateTime> Connects = new Queue<DateTime>();
            public readonly Queue<DateTime> Strikes = new Queue<DateTime>();
            public DateTime BannedUntil = DateTime.MinValue;
            public bool BanActive; // true until we've announced the expiry
            public DateTime KnownGoodUntil = DateTime.MinValue;
            public DateTime LastSeen;
            public int Offences;
        }

        private sealed class Verdict
        {
            public string? Reason;
            public string Kind = "";
            public LogLevel Level = LogLevel.Info;
            public bool AlreadyLogged;
            public bool Exempt;
        }

        // ------------------------------------------------------------------ state

        private Config _cfg = new Config();
        private HashSet<string> _whitelist = new HashSet<string>();
        private readonly object _lock = new object();
        private readonly Dictionary<string, IpRecord> _records = new Dictionary<string, IpRecord>();

        private string?[] _slotIp = new string?[0];
        private DateTime[] _slotConnectedAt = new DateTime[0];
        private DateTime[] _slotDroppedAt = new DateTime[0];
        private DateTime[] _bufFlaggedSince = new DateTime[0];
        private int[] _bufFlaggedBytes = new int[0];

        // sweeper (own thread)
        private Timer? _timer;
        private int _sweeping;
        private int _secondsSinceCleanup;
        private int _secondsSinceExpiryCheck;

        // diagnostics
        private long _connectEvents;

        // logging
        private readonly object _logLock = new object();
        private readonly Dictionary<string, (DateTime Last, int Suppressed)> _throttle =
            new Dictionary<string, (DateTime Last, int Suppressed)>();
        private readonly ConcurrentQueue<(LogLevel Level, string Text)> _chatQueue =
            new ConcurrentQueue<(LogLevel Level, string Text)>();

        private const string ConfigFileName = "AntiCrawler.json";
        private static readonly string ConfigPath = ResolveConfigPath();

        /// <summary>
        /// Config lives next to the plugin dll. TShock loads plugins from a byte array, so
        /// Assembly.Location is usually empty; in that case fall back to TShock's plugin directory
        /// (ServerPlugins), which is where the dll sits anyway.
        /// </summary>
        private static string ResolveConfigPath()
        {
            try
            {
                string loc = typeof(AntiCrawlerPlugin).Assembly.Location;
                string? dir = string.IsNullOrEmpty(loc) ? null : Path.GetDirectoryName(loc);
                if (!string.IsNullOrEmpty(dir)) return Path.Combine(dir, ConfigFileName);
            }
            catch { /* fall through */ }

            try
            {
                // looked up by name so a differently-named/internal property can't break compilation
                var prop = typeof(ServerApi).GetProperty("ServerPluginsDirectoryPath",
                    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                string? dir = prop?.GetValue(null) as string;
                if (!string.IsNullOrEmpty(dir)) return Path.GetFullPath(Path.Combine(dir, ConfigFileName));
            }
            catch { /* fall through */ }

            return Path.GetFullPath(Path.Combine("ServerPlugins", ConfigFileName));
        }

        public AntiCrawlerPlugin(Main game) : base(game) { }

        // ------------------------------------------------------------------ lifecycle

        public override void Initialize()
        {
            int n = Netplay.Clients.Length;
            _slotIp = new string?[n];
            _slotConnectedAt = new DateTime[n];
            _slotDroppedAt = new DateTime[n];
            _bufFlaggedSince = new DateTime[n];
            _bufFlaggedBytes = new int[n];
            for (int i = 0; i < n; i++)
            {
                _slotDroppedAt[i] = DateTime.MinValue;
                _bufFlaggedSince[i] = DateTime.MinValue;
            }

            LoadConfig();

            ServerApi.Hooks.ServerConnect.Register(this, OnConnect, -100);
            ServerApi.Hooks.ServerLeave.Register(this, OnLeave);
            ServerApi.Hooks.NetGetData.Register(this, OnGetData);
            ServerApi.Hooks.NetGreetPlayer.Register(this, OnGreet);

            Commands.ChatCommands.Add(new Command(AdminPermission, CmdAc, "anticrawler", "ac"));

            _timer = new Timer(_ => SweepGuarded(), null, 1000, 1000);

            Log(LogLevel.Info,
                $"v{Version} running with config: \n{_cfg.MaxConnectsPerWindow} connects/{_cfg.ConnectWindowSeconds}s; \n" +
                $"{_cfg.MaxConcurrentPerIp} concurrent/IP; \nhandshake timeout {_cfg.HandshakeTimeoutSeconds}s; \n" +
                $"{_cfg.StrikesBeforeBan} strikes -> {_cfg.InitialBanMinutes} min ban; ");
			Log(LogLevel.Info,				
                $"Console will show level >= {_cfg.ConsoleMinLevel}, SuperAdmin chat will show level{(_cfg.ChatEnabled ? $">= {_cfg.ChatMinLevel}" : "off")}.");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _timer?.Dispose();
                ServerApi.Hooks.ServerConnect.Deregister(this, OnConnect);
                ServerApi.Hooks.ServerLeave.Deregister(this, OnLeave);
                ServerApi.Hooks.NetGetData.Deregister(this, OnGetData);
                ServerApi.Hooks.NetGreetPlayer.Deregister(this, OnGreet);
                Commands.ChatCommands.RemoveAll(c => c.CommandDelegate == CmdAc);
            }
            base.Dispose(disposing);
        }

        /// <summary>
        /// Replace (not merge) collections: by default Newtonsoft adds the file's list items to the
        /// default list, which duplicated the whitelist entries on every restart.
        /// </summary>
        private static Config ParseConfig(string json)
        {
            var settings = new JsonSerializerSettings { ObjectCreationHandling = ObjectCreationHandling.Replace };
            var cfg = JsonConvert.DeserializeObject<Config>(json, settings) ?? new Config();
            // self-heal files that already contain duplicates
            cfg.Whitelist = (cfg.Whitelist ?? new List<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            return cfg;
        }

        private void LoadConfig()
        {
            string path = ConfigPath;
            bool existed = File.Exists(path);
            bool canWrite = true;

            try
            {
                if (existed)
                {
                    _cfg = ParseConfig(File.ReadAllText(path));
                    Log(LogLevel.Info, $"Loaded config from {path}");
                }
                else
                {
                    _cfg = new Config();

                    // carry over a config from the old location (tshock/AntiCrawler.json), if there is one
                    string legacy = Path.Combine(TShock.SavePath, ConfigFileName);
                    if (File.Exists(legacy))
                    {
                        _cfg = ParseConfig(File.ReadAllText(legacy));
                        Log(LogLevel.Info, $"Migrated config from {legacy}");
                    }
                }
            }
            catch (Exception ex)
            {
                // broken JSON: run on defaults but do NOT overwrite the user's file
                TShock.Log.ConsoleError($"[AntiCrawler] Config error in {path}, using defaults (file left untouched): {ex.Message}");
                _cfg = new Config();
                canWrite = false;
            }

            if (canWrite)
            {
                // always (re)write: creates a missing file and adds new options after plugin updates
                try
                {
                    string? dir = Path.GetDirectoryName(path);
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                    File.WriteAllText(path, JsonConvert.SerializeObject(_cfg, Formatting.Indented));
                    if (!existed) Log(LogLevel.Info, $"Created config at {path}");
                }
                catch (Exception ex)
                {
                    TShock.Log.ConsoleError($"[AntiCrawler] Could not write config to {path}: {ex.Message}");
                }
            }

            _whitelist = new HashSet<string>(_cfg.Whitelist, StringComparer.OrdinalIgnoreCase);
        }

        // ------------------------------------------------------------------ logging

        /// <summary>
        /// Writes to the console + TShock log and (for important events) queues a chat notification.
        /// throttleKey: repeated events with the same key are collapsed to one line per LogThrottleSeconds.
        /// Never takes _lock, so it is safe to call with _lock held.
        /// </summary>
        private void Log(LogLevel level, string msg, string? throttleKey = null)
        {
            bool toConsole = level >= _cfg.ConsoleMinLevel;
            bool toChat = _cfg.ChatEnabled && level >= _cfg.ChatMinLevel;
            if (!toConsole && !toChat) return;

            if (throttleKey != null)
            {
                lock (_logLock)
                {
                    var now = DateTime.UtcNow;
                    _throttle.TryGetValue(throttleKey, out var t);
                    if (t.Last != default(DateTime) && (now - t.Last).TotalSeconds < _cfg.LogThrottleSeconds)
                    {
                        _throttle[throttleKey] = (t.Last, t.Suppressed + 1);
                        return;
                    }
                    if (t.Suppressed > 0) msg += $" (+{t.Suppressed} similar suppressed)";
                    _throttle[throttleKey] = (now, 0);
                }
            }

            string line = $"[AntiCrawler] [{level.ToString().ToUpperInvariant()}] {msg}";

            try
            {
                if (toConsole)
                {
                    if (level >= LogLevel.Alert) TShock.Log.ConsoleError(line);
                    else TShock.Log.ConsoleInfo(line);
                }
            }
            catch { /* logging must never take the server down */ }

            if (toChat) _chatQueue.Enqueue((level, line));
        }

        private void PruneThrottle()
        {
            lock (_logLock)
            {
                var cutoff = DateTime.UtcNow.AddMinutes(-10);
                var dead = _throttle.Where(kv => kv.Value.Last < cutoff).Select(kv => kv.Key).ToList();
                foreach (var k in dead) _throttle.Remove(k);
            }
        }

        /// <summary>Rate-limited so a scan can't flood admin chat.</summary>
        private void FlushChat()
        {
            if (_chatQueue.IsEmpty) return;

            var batch = new List<(LogLevel Level, string Text)>();
            while (_chatQueue.TryDequeue(out var e)) batch.Add(e);

            try
            {
                var targets = TShock.Players
                    .Where(p => p != null && p.RealPlayer && p.ConnectionAlive && p.IsLoggedIn
                                && p.HasPermission(NotifyPermission))
                    .ToList();
                if (targets.Count == 0) return;

                int max = Math.Max(1, _cfg.ChatMaxPerSecond);
                foreach (var (level, text) in batch.Take(max))
                    foreach (var p in targets)
                        SendChat(p, level, text);

                if (batch.Count > max)
                    foreach (var p in targets)
                        p.SendWarningMessage($"[AntiCrawler] +{batch.Count - max} more events (see console).");
            }
            catch (Exception ex)
            {
                TShock.Log.ConsoleError($"[AntiCrawler] chat notify failed: {ex.Message}");
            }
        }

        private static void SendChat(TSPlayer p, LogLevel level, string text)
        {
            switch (level)
            {
                case LogLevel.Alert: p.SendErrorMessage(text); break;
                case LogLevel.Warning: p.SendWarningMessage(text); break;
                default: p.SendInfoMessage(text); break;
            }
        }

        // ------------------------------------------------------------------ helpers

        private static string? GetIp(int who)
        {
            try
            {
                var sock = Netplay.Clients[who].Socket;
                if (sock == null) return null;
                string? s = sock.GetRemoteAddress()?.ToString(); // "ip:port"
                if (string.IsNullOrEmpty(s)) return null;
                if (IPEndPoint.TryParse(s, out var ep)) return ep.Address.ToString();
                int i = s.LastIndexOf(':');
                return i > 0 ? s.Substring(0, i) : s;
            }
            catch { return null; }
        }

        /// <summary>Null-safe: the client table can be partly uninitialised right after startup.</summary>
        private static bool IsConn(int i)
        {
            try
            {
                var c = Netplay.Clients[i];
                return c != null && c.IsConnected();
            }
            catch { return false; }
        }

        /// <summary>
        /// A client we must not interfere with at the network-buffer level: fully in game (state 10),
        /// whitelisted, or from an IP that completed a real login recently. Call with _lock held.
        /// </summary>
        private bool IsTrusted(string? ip, int state, DateTime now)
        {
            if (state >= 10) return true;
            if (ip == null) return false;
            if (IsWhitelisted(ip)) return true;
            return _records.TryGetValue(ip, out var rec) && rec.KnownGoodUntil > now;
        }

        private bool IsWhitelisted(string ip) => _whitelist.Contains(ip);

        private IpRecord GetRecord(string ip, DateTime now)
        {
            if (!_records.TryGetValue(ip, out var rec))
                _records[ip] = rec = new IpRecord();
            rec.LastSeen = now;
            return rec;
        }

        private void ClearSlot(int who)
        {
            _slotIp[who] = null;
            _slotConnectedAt[who] = DateTime.MinValue;
            _slotDroppedAt[who] = DateTime.MinValue;
        }

        /// <summary>Politely asks the server loop to terminate a slot (silent: no packet sent back).</summary>
        private void Drop(int who)
        {
            try
            {
                lock (_lock)
                {
                    if (_slotDroppedAt[who] == DateTime.MinValue)
                        _slotDroppedAt[who] = DateTime.UtcNow;
                }
                var c = Netplay.Clients[who];
                if (c == null) return;
                c.PendingTermination = true;
                c.PendingTerminationApproved = true;
            }
            catch (Exception ex)
            {
                Log(LogLevel.Warning, $"Drop of slot {who} failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Doesn't wait for the (possibly wedged) server loop: resets the client and clears its receive buffer.
        /// Called with _lock held.
        /// </summary>
        private void HardReset(int who)
        {
            try { Netplay.Clients[who].Reset(); }
            catch (Exception ex) { Log(LogLevel.Alert, $"Reset of slot {who} FAILED: {ex.Message}"); }

            try
            {
                var mb = NetMessage.buffer[who];
                if (mb != null) lock (mb) mb.Reset();
            }
            catch (Exception ex) { Log(LogLevel.Alert, $"Buffer reset of slot {who} FAILED: {ex.Message}"); }

            ClearSlot(who);
            _bufFlaggedSince[who] = DateTime.MinValue;
        }

        // all of the following must be called with _lock held

        private void Strike(string ip, string why, DateTime now, int slot = -1)
        {
            var rec = GetRecord(ip, now);
            string where = slot >= 0 ? $"{ip} (slot {slot})" : ip;

            if (rec.KnownGoodUntil > now)
            {
                Log(LogLevel.Info, $"No strike for known-good {where}: {why}");
                return;
            }

            rec.Strikes.Enqueue(now);
            while (rec.Strikes.Count > 0 && (now - rec.Strikes.Peek()).TotalMinutes > _cfg.StrikeWindowMinutes)
                rec.Strikes.Dequeue();

            Log(LogLevel.Warning, $"Strike {rec.Strikes.Count}/{_cfg.StrikesBeforeBan} for {where}: {why}");

            if (rec.Strikes.Count >= _cfg.StrikesBeforeBan)
                Ban(ip, rec, now, why);
        }

        private void Ban(string ip, IpRecord rec, DateTime now, string why)
        {
            rec.Offences++;
            double minutes = Math.Min(_cfg.InitialBanMinutes * Math.Pow(2, rec.Offences - 1), _cfg.MaxBanMinutes);
            rec.BannedUntil = now.AddMinutes(minutes);
            rec.BanActive = true;
            rec.Strikes.Clear();
            rec.Connects.Clear();

            // free every slot this IP is currently holding
            int freed = 0;
            for (int i = 0; i < _slotIp.Length; i++)
            {
                if (_slotIp[i] == ip && IsConn(i))
                {
                    Drop(i);
                    freed++;
                }
            }

            Log(LogLevel.Alert,
                $"BANNED {ip} for {minutes:0} min (offence #{rec.Offences}), freed {freed} slot(s). Reason: {why}");
        }

        private int CountConnected(string ip, int exceptSlot)
        {
            int n = 0;
            for (int i = 0; i < _slotIp.Length; i++)
                if (i != exceptSlot && _slotIp[i] == ip && IsConn(i))
                    n++;
            return n;
        }

        /// <summary>Decides what to do with a newly seen connection. Called with _lock held.</summary>
        private Verdict EvaluateNew(int who, string? ip, DateTime now)
        {
            var v = new Verdict();
            v.Exempt = ip == null || IsWhitelisted(ip);
            if (v.Exempt) return v;

            var rec = GetRecord(ip!, now);

            if (rec.BannedUntil > now)
            {
                v.Kind = "banned";
                v.Reason = $"banned, {(rec.BannedUntil - now).TotalMinutes:0.#} min left";
                return v;
            }

            if (rec.KnownGoodUntil <= now)
            {
                rec.Connects.Enqueue(now);
                while (rec.Connects.Count > 0 &&
                       (now - rec.Connects.Peek()).TotalSeconds > _cfg.ConnectWindowSeconds)
                    rec.Connects.Dequeue();

                if (rec.Connects.Count > _cfg.MaxConnectsPerWindow)
                {
                    int count = rec.Connects.Count;
                    Ban(ip!, rec, now, $"connection flood ({count} connects in {_cfg.ConnectWindowSeconds}s)");
                    v.Kind = "flood";
                    v.Reason = "connection flood";
                    v.AlreadyLogged = true;
                    return v;
                }
            }

            int others = CountConnected(ip!, who);
            if (others >= _cfg.MaxConcurrentPerIp)
            {
                v.Kind = "concurrent";
                v.Level = LogLevel.Warning;
                v.Reason = $"too many concurrent connections ({others} already open, max {_cfg.MaxConcurrentPerIp})";
            }
            return v;
        }

        private void ApplyVerdict(int who, string? ip, Verdict v, bool foundBySweeper)
        {
            string via = foundBySweeper ? " [found by sweeper]" : "";
            if (v.Reason != null)
            {
                if (!v.AlreadyLogged)
                    Log(v.Level, $"Dropped slot {who} from {ip}: {v.Reason}{via}", $"drop:{ip}:{v.Kind}");
                Drop(who);
            }
            else if (ip == null)
            {
                Log(LogLevel.Debug, $"Slot {who}: could not resolve remote IP, not checked{via}");
            }
            else
            {
                Log(LogLevel.Debug, $"Allowed slot {who} from {ip}{(v.Exempt ? " (whitelisted)" : "")}{via}");
            }
        }

        // ------------------------------------------------------------------ hooks

        private void OnConnect(ConnectEventArgs args)
        {
            Interlocked.Increment(ref _connectEvents);

            int who = args.Who;
            if (who < 0 || who >= _slotIp.Length) return;

            string? ip = GetIp(who);
            var now = DateTime.UtcNow;
            Verdict v;

            lock (_lock)
            {
                _slotIp[who] = ip;
                _slotConnectedAt[who] = now;
                _slotDroppedAt[who] = DateTime.MinValue;
                v = EvaluateNew(who, ip, now);
            }

            ApplyVerdict(who, ip, v, false);
        }

        private void OnLeave(LeaveEventArgs args)
        {
            if (args.Who < 0 || args.Who >= _slotIp.Length) return;
            lock (_lock) ClearSlot(args.Who);
        }

        private void OnGreet(GreetPlayerEventArgs args)
        {
            if (args.Who < 0 || args.Who >= _slotIp.Length) return;

            string? ip;
            bool newlyTrusted = false;
            lock (_lock)
            {
                ip = _slotIp[args.Who];
                if (ip == null) return;
                var now = DateTime.UtcNow;
                var rec = GetRecord(ip, now);
                newlyTrusted = rec.KnownGoodUntil <= now;
                rec.KnownGoodUntil = now.AddHours(_cfg.KnownGoodHours);
                rec.Strikes.Clear();
                rec.Connects.Clear();
            }

            if (newlyTrusted)
                Log(LogLevel.Debug,
                    $"{ip} completed a real login (slot {args.Who}); exempt from rate limits for {_cfg.KnownGoodHours} h");
        }

        /// <summary>
        /// Only looks at slots still in State 0. The very first packet of a real client is always
        /// ConnectRequest (id 1) carrying a "Terraria###" version string.
        /// (Garbage that fails the size check in CheckBytes never reaches this hook - the sweeper covers that.)
        /// </summary>
        private void OnGetData(GetDataEventArgs args)
        {
            if (args.Handled) return;

            int who = args.Msg.whoAmI;
            if (who < 0 || who >= _slotIp.Length) return;
            var client = Netplay.Clients[who];
            if (client == null || client.State != 0) return;

            string? ip;
            lock (_lock) ip = _slotIp[who];
            if (ip == null || IsWhitelisted(ip)) return;

            string? problem = null;
            if (args.MsgID != PacketTypes.ConnectRequest)
            {
                problem = $"first packet was {args.MsgID}, not ConnectRequest";
            }
            else
            {
                try
                {
                    using (var ms = new MemoryStream(args.Msg.readBuffer, args.Index, args.Length))
                    using (var br = new BinaryReader(ms))
                    {
                        string version = br.ReadString();
                        if (version.Length > 16 || !version.StartsWith("Terraria", StringComparison.Ordinal))
                            problem = "bad version string in ConnectRequest";
                    }
                }
                catch
                {
                    problem = "unparseable ConnectRequest";
                }
            }

            if (problem == null) return;

            lock (_lock) Strike(ip, problem, DateTime.UtcNow, who);
            args.Handled = true;
            Drop(who);
        }

        // ------------------------------------------------------------------ sweeper (own thread)

        private void SweepGuarded()
        {
            if (Interlocked.Exchange(ref _sweeping, 1) == 1) return; // previous sweep still running
            try { Sweep(); }
            catch (Exception ex)
            {
                string where = (ex.StackTrace ?? "").Split('\n').FirstOrDefault()?.Trim() ?? "?";
                Log(LogLevel.Alert, $"Sweeper error: {ex.GetType().Name}: {ex.Message} @ {where}", "sweeper-error");
            }
            finally { Volatile.Write(ref _sweeping, 0); }
        }

        private void Sweep()
        {
            var now = DateTime.UtcNow;
            if (Netplay.Clients == null || NetMessage.buffer == null) return; // server not initialised yet

            lock (_lock)
            {
                for (int i = 0; i < _slotIp.Length; i++)
                {
                    var c = Netplay.Clients[i];

                    if (c == null) continue; // client table not fully initialised yet

                    // ---- 1. poisoned receive buffer: flagged for parsing, data never consumed
                    var mb = i < NetMessage.buffer.Length ? NetMessage.buffer[i] : null;
                    if (mb != null)
                    {
                        if (mb.checkBytes)
                        {
                            if (_bufFlaggedSince[i] == DateTime.MinValue)
                            {
                                _bufFlaggedSince[i] = now;
                                _bufFlaggedBytes[i] = mb.totalData;
                            }
                            else if ((now - _bufFlaggedSince[i]).TotalSeconds >= _cfg.StuckBufferSeconds
                                     && mb.totalData == _bufFlaggedBytes[i])
                            {
                                string? pip = _slotIp[i] ?? GetIp(i);

                                // Never touch the buffer of a connected, trusted client (in game, known-good
                                // or whitelisted). A legit client can't produce a malformed length prefix, so a
                                // "stuck" buffer there is a false positive and resetting it would kick a player.
                                if (c.IsConnected() && IsTrusted(pip, c.State, now))
                                {
                                    Log(LogLevel.Debug,
                                        $"Ignoring stuck receive buffer on trusted slot {i} ({pip ?? "?"}, state {c.State}, {mb.totalData} byte(s))",
                                        $"bufskip:{i}");
                                    _bufFlaggedSince[i] = DateTime.MinValue; // restart the stopwatch; re-checked later
                                }
                                else
                                {
                                    Log(LogLevel.Alert,
                                        $"Slot {i} ({pip ?? "?"}): receive buffer stuck for {(now - _bufFlaggedSince[i]).TotalSeconds:0}s " +
                                        $"with {mb.totalData} unread byte(s) - this is what loops 'Message size too small'. Clearing it and resetting the socket.");
                                    if (pip != null && !IsWhitelisted(pip)) Strike(pip, "malformed packet (poisoned buffer)", now, i);
                                    HardReset(i);
                                    continue;
                                }
                            }
                        }
                        else
                        {
                            _bufFlaggedSince[i] = DateTime.MinValue;
                        }
                    }

                    // ---- 2. not connected -> forget it
                    if (!c.IsConnected())
                    {
                        if (_slotIp[i] != null || _slotConnectedAt[i] != DateTime.MinValue)
                            ClearSlot(i);
                        continue;
                    }

                    // ---- 3. connected but ServerConnect never reported it -> evaluate it now
                    if (_slotConnectedAt[i] == DateTime.MinValue)
                    {
                        _slotConnectedAt[i] = now;
                        _slotDroppedAt[i] = DateTime.MinValue;
                        _slotIp[i] = GetIp(i);
                        Log(LogLevel.Info,
                            $"Slot {i} ({_slotIp[i] ?? "?"}) was connected but the ServerConnect hook never reported it; tracking it now.",
                            "untracked");
                        var v = EvaluateNew(i, _slotIp[i], now);
                        ApplyVerdict(i, _slotIp[i], v, true);
                    }

                    string? ip = _slotIp[i];

                    // ---- 4. dropped but still connected: the server loop isn't resetting it, do it ourselves
                    if (_slotDroppedAt[i] != DateTime.MinValue)
                    {
                        double sinceDrop = (now - _slotDroppedAt[i]).TotalSeconds;
                        if (sinceDrop >= 2)
                        {
                            Log(LogLevel.Warning,
                                $"Slot {i} ({ip ?? "?"}) still connected {sinceDrop:0}s after drop (state {c.State}); forcing reset");
                            HardReset(i);
                        }
                        continue;
                    }

                    if (c.State >= 10) continue; // fully in game
                    if (ip != null && IsWhitelisted(ip)) continue;

                    // ---- 5. timeouts
                    double age = (now - _slotConnectedAt[i]).TotalSeconds;

                    if (c.State == 0 && age > _cfg.HandshakeTimeoutSeconds)
                    {
                        Log(LogLevel.Info,
                            $"Slot {i} ({ip ?? "?"}) never sent a valid ConnectRequest in {age:0}s, dropping");
                        if (ip != null) Strike(ip, "handshake timeout", now, i);
                        Drop(i);
                    }
                    else if (c.State > 0 && age > _cfg.LoadingTimeoutSeconds)
                    {
                        // slow, not necessarily malicious: free the slot but no strike
                        Log(LogLevel.Info,
                            $"Slot {i} ({ip ?? "?"}) stuck in state {c.State} for {age:0}s, dropping (no strike)");
                        Drop(i);
                    }
                }

                // announce ban expiry (every ~10 s is plenty)
                if (++_secondsSinceExpiryCheck >= 10)
                {
                    _secondsSinceExpiryCheck = 0;
                    foreach (var kv in _records)
                    {
                        if (kv.Value.BanActive && kv.Value.BannedUntil <= now)
                        {
                            kv.Value.BanActive = false;
                            Log(LogLevel.Info, $"Ban expired for {kv.Key}");
                        }
                    }
                }

                if (++_secondsSinceCleanup >= 60)
                {
                    _secondsSinceCleanup = 0;
                    var keep = TimeSpan.FromHours(Math.Max(24, _cfg.KnownGoodHours));
                    var dead = _records
                        .Where(kv => kv.Value.BannedUntil < now && now - kv.Value.LastSeen > keep)
                        .Select(kv => kv.Key)
                        .ToList();
                    foreach (var k in dead) _records.Remove(k);
                    PruneThrottle();
                }
            }

            FlushChat();
        }

        // ------------------------------------------------------------------ command

        private void CmdAc(CommandArgs a)
        {
            string sub = a.Parameters.Count > 0 ? a.Parameters[0].ToLowerInvariant() : "status";
            var now = DateTime.UtcNow;

            switch (sub)
            {
                case "status":
                    {
                        a.Player.SendInfoMessage(
                            $"[AntiCrawler] v{Version} diag: ServerConnect events {Interlocked.Read(ref _connectEvents)}");
                        lock (_lock)
                        {
                            var bans = _records.Where(kv => kv.Value.BannedUntil > now).ToList();
                            a.Player.SendInfoMessage(
                                $"[AntiCrawler] tracking {_records.Count} IPs, {bans.Count} currently banned.");
                            foreach (var kv in bans.Take(20))
                                a.Player.SendInfoMessage(
                                    $"  {kv.Key}  {(kv.Value.BannedUntil - now).TotalMinutes:0}m left (offence #{kv.Value.Offences})");
                            if (bans.Count > 20) a.Player.SendInfoMessage($"  ...and {bans.Count - 20} more");
                        }
                    }
					//fall through. status should show everything
                    goto case "slots";

                case "slots":
                    lock (_lock)
                    {
                        int shown = 0;
                        for (int i = 0; i < _slotIp.Length; i++)
                        {
                            var c = Netplay.Clients[i];
                            var mb = i < NetMessage.buffer.Length ? NetMessage.buffer[i] : null;
                            bool flagged = mb != null && mb.checkBytes;
                            if (c == null || (!c.IsConnected() && !flagged)) continue;

                            string ip = _slotIp[i] ?? GetIp(i) ?? "?";
                            double age = _slotConnectedAt[i] == DateTime.MinValue
                                ? 0 : (now - _slotConnectedAt[i]).TotalSeconds;
                            a.Player.SendInfoMessage(
                                $"  slot {i,3}  state {c.State,2}  {ip,-39}  {age:0}s" +
                                (mb != null ? $"  buf {mb.totalData}B{(flagged ? "*" : "")}" : "") +
                                (c.IsConnected() ? "" : "  [no socket]") +
                                (_slotDroppedAt[i] != DateTime.MinValue ? "  [dropping]" : ""));
                            shown++;
                        }
                        a.Player.SendInfoMessage($"[AntiCrawler] {shown} slot(s) listed. (* = buffer flagged for parsing)");
                    }
                    break;

                case "unban":
                    if (a.Parameters.Count < 2) { a.Player.SendErrorMessage("Usage: /ac unban <ip>"); break; }
                    {
                        string target = a.Parameters[1];
                        bool removed;
                        lock (_lock) removed = _records.Remove(target);
                        if (removed)
                        {
                            a.Player.SendSuccessMessage($"Cleared {target}.");
                            Log(LogLevel.Info, $"{a.Player.Name} cleared all records/bans for {target}");
                        }
                        else
                        {
                            a.Player.SendErrorMessage("No record for that IP.");
                        }
                    }
                    break;

                case "reload":
                    LoadConfig();
                    a.Player.SendSuccessMessage("[AntiCrawler] config reloaded.");
                    Log(LogLevel.Info, $"Config reloaded by {a.Player.Name}");
                    break;

                default:
                    a.Player.SendErrorMessage("Usage: /ac [status|slots|unban <ip>|reload]");
                    break;
            }
        }
    }
}
