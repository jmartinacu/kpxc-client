package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

const usage = `kpxc-client - query the KeePassXC database unlocked in the GUI

The GUI must have Browser Integration enabled and the database unlocked.
Socket: $KPXC_SOCKET or $XDG_RUNTIME_DIR/kpxc_server (on WSL2 this socket
is bridged to the Windows GUI's named pipe; on native Linux the GUI's own
socket is used directly).

Usage:
  kpxc-client configure                 Associate with the current database
  kpxc-client db-hash                   Print the current database hash
  kpxc-client groups                    List groups in the database
  kpxc-client list [-a] [--url URL]     List entries (all, or matching URL)
  kpxc-client get --url URL [options]   Print one field of a matching entry
  kpxc-client totp --uuid UUID          Print the current TOTP for an entry
  kpxc-client generate                  Generate a password using GUI settings
  kpxc-client lock                      Lock the database
  kpxc-client git-credential <op>       Git credential helper (get/store/erase)

Field selection for "get": --field password|username|title|url|uuid|KPH: <name>.
Custom attributes (Attributes tab) must be named with a "KPH: " prefix in
KeePassXC or they are not exposed to the protocol.
`

// entry is one login returned by get-logins / get-all-logins.
type entry map[string]any

func (e entry) str(k string) string {
	if v, ok := e[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (e entry) attr(name string) (string, bool) {
	if name == "password" {
		return e.str("password"), true
	}
	if name == "username" {
		return e.str("login"), true
	}
	if name == "title" {
		return e.str("name"), true
	}
	if sf, ok := e["stringFields"].([]any); ok {
		for _, raw := range sf {
			if m, ok := raw.(map[string]any); ok {
				if v, ok := m[name]; ok {
					if s, ok := v.(string); ok {
						return s, true
					}
				}
			}
		}
	}
	if v, ok := e[name]; ok {
		if s, ok := v.(string); ok {
			return s, true
		}
	}
	return "", false
}

func main() {
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	socket := flag.String("socket", "", "KeePassXC browser socket (default $XDG_RUNTIME_DIR/kpxc_server)")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	path := *socket
	if path == "" {
		path = SocketPath()
	}

	var err error
	switch args[0] {
	case "git-credential":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: kpxc-client git-credential <get|store|erase>")
			os.Exit(2)
		}
		err = gitCredential(path, args[1])
	case "configure":
		err = cmdConfigure(path)
	case "db-hash":
		err = withClient(path, func(c *Client) error {
			h, err := databaseHash(c)
			if err == nil {
				fmt.Println(h)
			}
			return err
		})
	case "groups":
		err = cmdGroups(path)
	case "list":
		err = cmdList(path, args[1:])
	case "get":
		err = cmdGet(path, args[1:])
	case "totp":
		err = cmdTOTP(path, args[1:])
	case "generate":
		err = withClient(path, func(c *Client) error {
			resp, err := c.request("generate-password", nil)
			if err != nil {
				return err
			}
			var out struct {
				Password string `json:"password"`
			}
			if err := json.Unmarshal(resp, &out); err != nil {
				return err
			}
			fmt.Println(out.Password)
			return nil
		})
	case "lock":
		err = withClient(path, func(c *Client) error {
			_, err := c.request("lock-database", nil)
			return err
		})
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], usage)
		os.Exit(2)
	}

	if err != nil {
		if IsDatabaseLocked(err) {
			fmt.Fprintln(os.Stderr, "database is locked: unlock KeePassXC in the GUI and retry")
		} else {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func withClient(socket string, fn func(*Client) error) error {
	c, err := Dial(socket)
	if err != nil {
		return err
	}
	defer c.Close()
	return fn(c)
}

// withAssociated runs fn with an associated identity.
func withAssociated(socket string, fn func(c *Client, id *identity) error) error {
	ks, err := LoadKeyStore()
	if err != nil {
		return fmt.Errorf("loading key store: %w", err)
	}
	return withClient(socket, func(c *Client) error {
		id, err := associate(c, ks)
		if err != nil {
			return err
		}
		return fn(c, id)
	})
}

func cmdConfigure(socket string) error {
	ks, err := LoadKeyStore()
	if err != nil {
		return err
	}
	return withClient(socket, func(c *Client) error {
		id, err := associate(c, ks)
		if err != nil {
			return err
		}
		fmt.Printf("associated with database %s as %q\n", id.dbHash, id.id)
		return nil
	})
}

func cmdGroups(socket string) error {
	return withAssociated(socket, func(c *Client, id *identity) error {
		resp, err := c.request("get-database-groups", map[string]any{
			"keys": []map[string]string{{"id": id.id, "key": id.idPubB64}},
		})
		if err != nil {
			return err
		}
		var out struct {
			Groups struct {
				Groups []group `json:"groups"`
			} `json:"groups"`
		}
		if err := json.Unmarshal(resp, &out); err != nil {
			return err
		}
		for _, g := range out.Groups.Groups {
			printGroup(g, "")
		}
		return nil
	})
}

type group struct {
	Name     string  `json:"name"`
	UUID     string  `json:"uuid"`
	Children []group `json:"children"`
}

func printGroup(g group, indent string) {
	fmt.Printf("%s%s\n", indent, g.Name)
	for _, ch := range g.Children {
		printGroup(ch, indent+"  ")
	}
}

func cmdList(socket string, args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	all := fs.Bool("a", false, "list all entries in the database")
	allAlias := fs.Bool("all", false, "list all entries in the database")
	url := fs.String("url", "", "list entries matching this URL")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *allAlias {
		*all = true
	}
	if !*all && *url == "" {
		return fmt.Errorf("list requires --url URL or --all")
	}
	return withAssociated(socket, func(c *Client, id *identity) error {
		entries, err := getLogins(c, id, *url, *all)
		if err != nil {
			return err
		}
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(entries)
		}
		for _, e := range entries {
			fmt.Printf("%s\t%s\t%s\n", e.str("name"), e.str("login"), e.str("url"))
		}
		return nil
	})
}

func getLogins(c *Client, id *identity, url string, all bool) ([]entry, error) {
	action := "get-logins"
	inner := map[string]any{
		"keys": []map[string]string{{"id": id.id, "key": id.idPubB64}},
	}
	if all {
		action = "get-all-logins"
	} else {
		inner["url"] = url
		inner["submitUrl"] = url
	}
	resp, err := c.request(action, inner)
	if err != nil {
		return nil, err
	}
	var out struct {
		Entries []entry `json:"entries"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

func cmdGet(socket string, args []string) error {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	url := fs.String("url", "", "entry URL")
	username := fs.String("username", "", "filter by username")
	field := fs.String("field", "password", "password|username|title|url|uuid|KPH:<name>")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" {
		return fmt.Errorf("get requires --url URL")
	}
	return withAssociated(socket, func(c *Client, id *identity) error {
		entries, err := getLogins(c, id, *url, false)
		if err != nil {
			return err
		}
		if *username != "" {
			filtered := entries[:0]
			for _, e := range entries {
				if e.str("login") == *username {
					filtered = append(filtered, e)
				}
			}
			entries = filtered
		}
		if len(entries) == 0 {
			return fmt.Errorf("no matching entry")
		}
		if len(entries) > 1 {
			names := []string{}
			for _, e := range entries {
				names = append(names, e.str("name")+" ("+e.str("login")+")")
			}
			sort.Strings(names)
			return fmt.Errorf("multiple entries match, disambiguate with --username: %s",
				strings.Join(names, ", "))
		}
		v, ok := entries[0].attr(*field)
		if !ok {
			return fmt.Errorf("entry has no field %q", *field)
		}
		fmt.Println(v)
		return nil
	})
}

func cmdTOTP(socket string, args []string) error {
	fs := flag.NewFlagSet("totp", flag.ExitOnError)
	uuid := fs.String("uuid", "", "entry UUID (see kpxc-client list --json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uuid == "" {
		return fmt.Errorf("totp requires --uuid UUID")
	}
	return withAssociated(socket, func(c *Client, _ *identity) error {
		resp, err := c.request("get-totp", map[string]any{"uuid": *uuid})
		if err != nil {
			return err
		}
		var out struct {
			TOTP string `json:"totp"`
		}
		if err := json.Unmarshal(resp, &out); err != nil {
			return err
		}
		if out.TOTP == "" {
			return fmt.Errorf("entry has no TOTP configured")
		}
		fmt.Println(out.TOTP)
		return nil
	})
}

// gitCredential implements the git-credential helper protocol.
func gitCredential(socket, op string) error {
	if op == "erase" {
		return nil
	}
	in := map[string]string{}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			in[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	switch op {
	case "get":
		if in["url"] == "" {
			return fmt.Errorf("git-credential get requires a url")
		}
		return withAssociated(socket, func(c *Client, id *identity) error {
			entries, err := getLogins(c, id, in["url"], false)
			if err != nil {
				if IsDatabaseLocked(err) {
					return err
				}
				return nil // no match is not fatal for git
			}
			var chosen entry
			for _, e := range entries {
				if in["username"] == "" || e.str("login") == in["username"] {
					chosen = e
					break
				}
			}
			if chosen == nil {
				return nil
			}
			fmt.Printf("username=%s\npassword=%s\n", chosen.str("login"), chosen.str("password"))
			return nil
		})
	case "store":
		if in["url"] == "" || in["username"] == "" {
			return nil
		}
		return withAssociated(socket, func(c *Client, id *identity) error {
			_, err := c.request("set-login", map[string]any{
				"url":      in["url"],
				"login":    in["username"],
				"password": in["password"],
			})
			return err
		})
	default:
		return fmt.Errorf("unsupported git-credential operation %q", op)
	}
}
