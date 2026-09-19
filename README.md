# kpxc-client

Go client for KeePassXC's [browser-integration protocol]. Queries the
database that is already unlocked in the KeePassXC GUI - no master password
retrieved or re-typed by this tool.

The GUI must have Browser Integration enabled and the database unlocked.
The client connects to a Unix domain socket: `$KPXC_SOCKET`, or
`$XDG_RUNTIME_DIR/kpxc_server` by default.

- **Native Linux:** the GUI exposes that socket directly; no extra setup.
- **WSL2:** the GUI runs on Windows, so the socket must be bridged from
  its named pipe
  (`\\.\pipe\org.keepassxc.KeePassXC.BrowserServer_<user>`)
  via socat + npiperelay - see
  [docs/wsl2-keepassxc-setup.md](docs/wsl2-keepassxc-setup.md) for the
  full bridge setup and troubleshooting.

## Commands

```
kpxc-client configure                # associate (one dialog in the GUI)
kpxc-client db-hash                  # current database hash
kpxc-client groups                   # group tree
kpxc-client list [-a|--all] [--url URL] [--json]
kpxc-client get --url URL [--username U] [--field password|username|title|url|uuid|KPH: <name>]
kpxc-client totp --uuid UUID
kpxc-client generate
kpxc-client lock
kpxc-client git-credential <get|store|erase>   # git credential helper
```

Association identities are stored in `~/.config/kpxc-client/keys.json`
(0600), keyed by database hash.

## Custom entry attributes (`KPH: ` prefix)

KeePassXC only exposes an entry's custom attributes (the entry's
*Attributes* tab) to browser-integration clients when the attribute
**name starts with `KPH: `** - the prefix plus one space. This is a
deliberate security filter in KeePassXC: attributes without the prefix
are never sent over the socket, so `--field "KPH: ..."` fails with
`entry has no field` even though the attribute exists in the GUI.

To read one:

1. In KeePassXC, open the entry's *Attributes* tab.
2. Rename (or create) the attribute with the prefix, e.g.
   `KPH: KPXC Atr`.
3. Read it:

       kpxc-client get --url https://kpxc.example --field "KPH: KPXC Atr"

The value is printed in cleartext; protect the attribute in the GUI if it
is sensitive.

## Git integration

```
git config --global credential.helper '!f() { kpxc-client git-credential "$@"; }; f'
```

## Not supported by the protocol

- Custom attributes without the `KPH: ` prefix are never sent by
  KeePassXC (see above).
- `list --all` (`get-all-logins`) is not implemented by the KeePassXC
  2.7.x server; `list --url` and `get --url` work.
- Attachments cannot be read via the browser protocol; use `keepassxc-cli
attachment-export` against the `.kdbx` file for those.

[browser-integration protocol]: https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md
