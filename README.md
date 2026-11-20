# AntiCrawler-TShock-Plugin
Prevents crawler bots from connecting to a Terraria TShock server, kicking and temporarily banning them. All info is logged to the server console and sent in chat to superAdmins and players with the anticrawler.notify permission node.

A config file is automatically created in the plugins directory at first run, and can be freely edited and live-reloaded via the specific command.

These are the defaults and explanations:
```
{
  "HandshakeTimeoutSeconds": 10,   after how many seconds a connection is dropped if it never sends a valid Terraria ConnectRequest (earns a strike)
  "LoadingTimeoutSeconds": 180,    how long a client may sit in the login/loading phase (password, world download, before it is fully in game) before it is dropped; slow but not malicious, so no strike
  "MaxConcurrentPerIp": 4,         how many sockets one IP may hold open at once; extra ones are dropped (no ban). Keep it above 1 for households sharing one IP
  "ConnectWindowSeconds": 30,      length of the sliding window used for counting new connections from one IP
  "MaxConnectsPerWindow": 8,       more than this many new connections from one IP inside that window counts as a flood and bans the IP immediately
  "StrikesBeforeBan": 3,           how many strikes an IP can collect (handshake timeouts, bad first packets, stuck buffers) before it is banned
  "StrikeWindowMinutes": 10,       strikes older than this expire, so only strikes within this period count towards a ban
  "InitialBanMinutes": 30,         length of an IP's first ban; every repeat offence doubles it (30, 60, 120, ...)
  "MaxBanMinutes": 1440,           upper limit for the doubling, in minutes (1440 = 24 hours)
  "KnownGoodHours": 12,            after an IP completes a real login it is trusted for this long: exempt from the connect-rate limit and from strikes (it is still dropped by timeouts, just not penalised)
  "StuckBufferSeconds": 3,         how long a connection's receive buffer may stay flagged for parsing with unchanged data before it is treated as poisoned and cleared (trusted connected players are skipped)
  "Whitelist": [                   
    "127.0.0.1",                   IPs that are never rate-limited, struck or banned, and whose buffers are never touched. Exact addresses only, no ranges. Add your own IP or a reverse proxy here
    "::1"
  ],
  "ConsoleMinLevel": "Info",       lowest level written to the console and TShock log: Debug (also includes every allowed connection), Info, Warning, Alert
  "ChatEnabled": true,             send events to online players who have the anticrawler.notify permission (superadmins have it automatically)
  "ChatMinLevel": "Warning",       lowest level sent to those players in chat
  "ChatMaxPerSecond": 5,           most chat lines each admin receives per second; anything beyond that is replaced by a "+N more events (see console)" line
  "LogThrottleSeconds": 10         identical repeating events (for example a banned IP reconnecting over and over) are logged once per this many seconds, with a "+N similar suppressed" note
}
```

### Commands:

`/ac` or `/ac status`

prints currently tracking IPs, how many are banned, how many connections were tried since last server boot, how many player slots are occupied

`/ac slots`

prints how many player slots are occupied


`/ac unban ip`

unbans an IP address

and again equal to

`/ac reload`

reloads the config file

------
## INSTALLATION:
Just drop the `CaseInsensitiveLogin.dll` from the [Releases tab](https://github.com/red9350/AntiCrawler-TShock-Plugin/releases) to your ServerPlugins directory and restart TShock
