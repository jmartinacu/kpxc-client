// Package main implements a Go client for KeePassXC's browser-integration
// protocol (https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md).
//
// It speaks newline-delimited JSON over a Unix domain socket (the same socket
// the Linux KeePassXC GUI exposes at $XDG_RUNTIME_DIR/kpxc_server). On WSL2
// that socket is bridged to the Windows named pipe \\.\pipe\org.keepassxc.KeePassXC.BrowserServer_<user> via
// socat + npiperelay, which lets the tool query the database already
// unlocked in the Windows GUI.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

// DefaultSocketName is the socket file name used by the KeePassXC GUI.
const DefaultSocketName = "kpxc_server"

// SocketPath resolves the KeePassXC browser-integration socket, honouring
// KPXC_SOCKET and falling back to $XDG_RUNTIME_DIR/kpxc_server then /tmp.
func SocketPath() string {
	if p := os.Getenv("KPXC_SOCKET"); p != "" {
		return p
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return filepath.Join(x, DefaultSocketName)
	}
	return filepath.Join("/tmp", DefaultSocketName)
}

// envelope is the outer, partially-encrypted protocol frame.
type envelope struct {
	Action    string `json:"action"`
	Message   string `json:"message,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	ClientID  string `json:"clientID,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
	RequestID string `json:"requestID,omitempty"`
}

// flexBool accepts JSON booleans and the string-encoded booleans
// ("true"/"false") that the named-pipe transport sends.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), "\"")
	switch s {
	case "true", "1":
		*b = true
	case "false", "0", "null", "":
		*b = false
	default:
		return fmt.Errorf("invalid boolean %q", s)
	}
	return nil
}

// response is the outer frame KeePassXC sends back.
type response struct {
	Action    string          `json:"action"`
	Message   string          `json:"message,omitempty"`
	Nonce     string          `json:"nonce,omitempty"`
	Success   flexBool        `json:"success"`
	Error     string          `json:"error"`
	ErrorCode *flexInt        `json:"errorCode"`
	Version   string          `json:"version"`
	PublicKey string          `json:"publicKey"`
	Raw       json.RawMessage `json:"-"`
}

// innerError mirrors error fields KeePassXC puts inside encrypted messages.
type innerError struct {
	Error     string   `json:"error"`
	ErrorCode *flexInt `json:"errorCode"`
}

// flexInt accepts JSON numbers and quoted numbers, as the named-pipe
// transport sends them.
type flexInt int

func (i *flexInt) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), "\"")
	if s == "null" || s == "" {
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid integer %q: %w", s, err)
	}
	*i = flexInt(v)
	return nil
}

// ProtocolError is an application-level error returned by KeePassXC.
type ProtocolError struct {
	Code int
	Msg  string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("keepassxc: %s (error code %d)", e.Msg, e.Code)
}

// well-known error codes
const (
	errDatabaseNotOpened = 1
	errNoLoginsFound     = 15
)

// IsDatabaseLocked reports whether the error means the GUI is locked.
func IsDatabaseLocked(err error) bool {
	var pe *ProtocolError
	if errors.As(err, &pe) {
		return pe.Code == errDatabaseNotOpened || pe.Msg == "Database not opened"
	}
	return false
}

// Client is one encrypted session with the KeePassXC GUI.
type Client struct {
	conn       net.Conn
	rw         *bufio.ReadWriter
	dec        *json.Decoder
	clientID   string
	clientPub  *[32]byte
	clientPriv *[32]byte
	hostPub    *[32]byte
}

// Dial connects to the socket and performs the change-public-keys handshake.
func Dial(socket string) (*Client, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to KeePassXC socket %s: %w", socket, err)
	}
	c := &Client{conn: conn, rw: bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))}
	c.dec = json.NewDecoder(c.rw.Reader)

	var id [24]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	c.clientID = base64.StdEncoding.EncodeToString(id[:])
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	c.clientPub, c.clientPriv = pub, priv

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	if err := c.writeJSON(&envelope{
		Action:    "change-public-keys",
		PublicKey: base64.StdEncoding.EncodeToString(pub[:]),
		Nonce:     base64.StdEncoding.EncodeToString(nonce[:]),
		ClientID:  c.clientID,
	}); err != nil {
		return nil, err
	}
	resp, err := c.readEnvelope()
	if err != nil {
		return nil, err
	}
	if resp.PublicKey == "" {
		return nil, fmt.Errorf("keepassxc did not return a host public key")
	}
	hostPub, err := decodeKey(resp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid host public key: %w", err)
	}
	c.hostPub = hostPub
	return c, nil
}

// Close terminates the session.
func (c *Client) Close() error { return c.conn.Close() }

func decodeKey(s string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	var k [32]byte
	copy(k[:], raw)
	return &k, nil
}

func (c *Client) writeJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := c.rw.Write(append(data, '\n')); err != nil {
		return err
	}
	return c.rw.Flush()
}

func (c *Client) readEnvelope() (*response, error) {
	var resp response
	// The Linux GUI socket frames messages with newlines, but the
	// Windows named pipe (bridged here) sends bare JSON objects, so
	// decode a stream value rather than reading newline-terminated lines.
	if err := c.dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading from KeePassXC: %w", err)
	}
	return &resp, nil
}

// request sends an encrypted request and returns the decrypted response
// body as raw JSON. inner must be a JSON object; it is augmented with the
// action name and request nonce.
func (c *Client) request(action string, inner map[string]any) (json.RawMessage, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce[:])

	if inner == nil {
		inner = map[string]any{}
	}
	inner["action"] = action
	inner["nonce"] = nonceB64
	payload, err := json.Marshal(inner)
	if err != nil {
		return nil, err
	}

	sealed := box.Seal(nil, payload, &nonce, c.hostPub, c.clientPriv)
	env := &envelope{
		Action:   action,
		Message:  base64.StdEncoding.EncodeToString(sealed),
		Nonce:    nonceB64,
		ClientID: c.clientID,
	}
	if err := c.writeJSON(env); err != nil {
		return nil, err
	}
	resp, err := c.readEnvelope()
	if err != nil {
		return nil, err
	}
	if resp.Message == "" {
		if resp.Error != "" || resp.ErrorCode != nil {
			return nil, protocolErr(resp.ErrorCode, resp.Error)
		}
		return nil, fmt.Errorf("empty response for action %q", action)
	}
	if resp.Nonce != "" {
		// server nonce must equal request nonce + 1
		if !nonceIncremented(nonceB64, resp.Nonce) {
			return nil, fmt.Errorf("bad response nonce: got %s want %s", resp.Nonce, nonceB64)
		}
	}
	var respNonce [24]byte
	raw, err := base64.StdEncoding.DecodeString(resp.Nonce)
	if err != nil || len(raw) != 24 {
		copy(respNonce[:], mustB64Decode(nonceB64))
		incrementNonce(&respNonce)
	} else {
		copy(respNonce[:], raw)
	}
	sealedMsg, err := base64.StdEncoding.DecodeString(resp.Message)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted message: %w", err)
	}
	plain, ok := box.Open(nil, sealedMsg, &respNonce, c.hostPub, c.clientPriv)
	if !ok {
		return nil, fmt.Errorf("cannot decrypt KeePassXC response")
	}

	var ie innerError
	if err := json.Unmarshal(plain, &ie); err == nil {
		if ie.Error != "" || ie.ErrorCode != nil {
			return nil, protocolErr(ie.ErrorCode, ie.Error)
		}
	}
	return json.RawMessage(plain), nil
}

func protocolErr(code *flexInt, msg string) error {
	pe := &ProtocolError{Msg: msg}
	if code != nil {
		pe.Code = int(*code)
	}
	return pe
}

func mustB64Decode(s string) []byte {
	raw, _ := base64.StdEncoding.DecodeString(s)
	return raw
}

// nonceIncremented checks that got equals want after a 24-byte increment.
// The reference protocol increments the last byte (little-endian), but the
// Windows/named-pipe build of KeePassXC 2.7.x increments the first byte;
// accept both conventions.
func nonceIncremented(want, got string) bool {
	w, err1 := base64.StdEncoding.DecodeString(want)
	g, err2 := base64.StdEncoding.DecodeString(got)
	if err1 != nil || err2 != nil || len(w) != 24 || len(g) != 24 {
		return false
	}
	if string(w) == string(g) {
		return true
	}
	little := make([]byte, 24)
	copy(little, w)
	little[23]++
	if string(little) == string(g) {
		return true
	}
	big := make([]byte, 24)
	copy(big, w)
	big[0]++
	return string(big) == string(g)
}

func incrementNonce(n *[24]byte) {
	for i := 23; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
}
