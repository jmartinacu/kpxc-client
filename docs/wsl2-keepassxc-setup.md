# KeePassXC ↔ WSL2 socket integration (Windows 11 ARM64)

This documents how `kpxc-client` in this repo is wired to the KeePassXC GUI
running on Windows, what was broken, and how it was fixed on this machine.

## The setup

```
kpxc-client (WSL2)
   │  Unix domain socket
   ▼
$XDG_RUNTIME_DIR/kpxc_server          (created by socat, systemd user unit)
   │  stdin/stdout
   ▼
npiperelay.exe                        (Windows exe, runs via WSL interop)
   │  Windows named pipe
   ▼
\\.\pipe\org.keepassxc.KeePassXC.BrowserServer_jmart
   │
   ▼
KeePassXC 2.7.12 (Windows)            (database unlocked, Browser Integration enabled)
```

## What was broken

Running `kpxc-client configure` failed with:

```
error: cannot connect to KeePassXC socket /run/user/1000/kpxc_server:
dial unix /run/user/1000/kpxc_server: connect: no such file or directory
```

The socket simply did not exist. The repo's docs assumed a
`\\.\pipe\kpxc_server` named pipe on the Windows side, but:

1. **No bridge existed.** Nothing was relaying the Windows named pipe into
   the WSL2 Unix socket; the `socat + npiperelay` relay the README referred
   to had never been set up on this machine.
2. **The pipe name changed.** Modern KeePassXC (2.7.x) does not use
   `\\.\pipe\kpxc_server`. Its browser-integration pipe is per-user:
   `\\.\pipe\org.keepassxc.KeePassXC.BrowserServer_<windows-user>` (here:
   `..._jmart`). It only exists while KeePassXC runs with
   *Settings → Browser Integration → Enable browser integration* on
   (it was already enabled).

## The fix (system side)

### 1. Build npiperelay.exe for Windows ARM64

[npiperelay](https://github.com/jstarks/npiperelay) relays a Windows named
pipe to stdin/stdout. Cross-compile it in WSL (Go handles Windows ARM64;
also runs fine via emulation if needed):

```sh
cd /tmp
GOOS=windows GOARCH=arm64 GOBIN= GOPATH=~/go \
  go install -buildvcs=false github.com/albertony/npiperelay@latest
# note: a plain `go install` fails with "cannot install cross-compiled
# binaries when GOBIN is set"; clear GOBIN for the cross build

cp ~/go/bin/windows_arm64/npiperelay.exe ~/.local/bin/
```

(`GOBIN=` is required because cross-compiled binaries go to
`$GOPATH/bin/<GOOS>_<GOARCH>/` and Go refuses when `GOBIN` is set.)

### 2. socat bridge as a systemd user unit

`~/.config/systemd/user/kpxc-bridge.service`:

```ini
[Unit]
Description=Bridge KeePassXC browser socket to Windows named pipe
After=graphical-session.target

[Service]
ExecStart=/usr/bin/socat UNIX-LISTEN:%t/kpxc_server,fork EXEC:"%h/.local/bin/npiperelay.exe -ep -s //./pipe/org.keepassxc.KeePassXC.BrowserServer_jmart"
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
```

Details that matter:

- `%t` = `$XDG_RUNTIME_DIR` (so the socket lands in `/run/user/1000`,
  where `SocketPath()` looks for it). Do **not** use `%h` — that expands
  to the home directory and the client will not find the socket.
- `fork` lets socat accept one connection per request; each spawns a fresh
  `npiperelay.exe` via WSL interop.
- The pipe name embeds the Windows username — adjust if the Windows
  account changes.

Enable it:

```sh
systemctl --user daemon-reload
systemctl --user enable --now kpxc-bridge.service
```

Verify: `ls -l /run/user/1000/kpxc_server` shows the socket, and
`kpxc-client db-hash` returns a hash.

## The fix (client side)

With the bridge up, the client still failed. Root causes, verified against
the KeePassXC 2.7.12 source (`src/browser/BrowserAction.cpp`,
`BrowserService.cpp` in the `keepassxreboot/keepassxc` repo):

1. **No newline framing on the pipe.** The Linux GUI socket terminates
   messages with `\n`; the named pipe sends bare JSON objects, so the
   line-based reader (`ReadBytes('\n')`) blocked forever.
   Fix: `readEnvelope` now decodes with `json.Decoder` on a stream.

2. **String-encoded booleans and integers.** The pipe transport sends
   `"success":"true"` and `"errorCode":"8"` as strings, which failed
   unmarshalling into `bool`/`*int`. Fix: `flexBool` / `flexInt` types
   accept both forms.

3. **Nonce increment convention.** This build increments the *first* byte
   of the 24-byte nonce, not the last (TweetNaCl little-endian
   convention). Fix: the response-nonce check accepts either.

4. **`associate` sent the wrong key.** Per
   [keepassxc-protocol.md](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md),
   the `key` field must be the *session* public key from
   `change-public-keys` (`m_clientPublicKey` in the server); `idKey` is the
   permanent identification key stored in the database. The client sent the
   identity key as `key`, so the server rejected association with error 8
   **without ever showing the GUI dialog** (which is why nothing popped up
   in Windows). Fix: `key` = session public key, `idKey` = identity key.

5. **`get-database-groups` response shape.** The payload is double-nested:
   `{"groups": {"groups": [...]}}`. Fix: unwrap the outer object.

6. **Custom attributes are prefix-gated.** KeePassXC only exposes custom
   attributes (entry *Attributes* tab) whose name starts with `KPH: `
   (prefix plus space). `get --field "KPH: <name>"` reads them; the client
   now unwraps the `stringFields` array they arrive in. See README.md.

## Known limitations

- `list --all` / `get-all-logins` is not implemented by the KeePassXC
  2.7.x server (error 12, "incorrect action"). Use `list --url` /
  `get --url`.
- `generate` requires the GUI password-generator dialog and an async
  passive response; untested.

## Quick health check

```sh
systemctl --user is-active kpxc-bridge.service   # active
ls -l /run/user/1000/kpxc_server                 # socket exists
kpxc-client db-hash                              # prints hash
powershell.exe -NoProfile -Command "[System.IO.Directory]::GetFiles('\\\\.\\pipe\\')" \
  | tr ',' '\n' | grep -i keepass                # pipe present while GUI runs
```

If the socket disappears, check that KeePassXC is running on Windows (the
named pipe only exists while it does) and that the service restarted it:
`journalctl --user -u kpxc-bridge.service -n 20`.
