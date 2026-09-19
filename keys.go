package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/nacl/box"
)

// StoredKey is the persistent identification key pair for one database.
type StoredKey struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
	SecretKey string `json:"secretKey,omitempty"`
}

// KeyStore persists association identities, keyed by database hash.
type KeyStore struct {
	path      string
	Databases map[string]StoredKey `json:"databases"`
}

func keyStorePath() string {
	if p := os.Getenv("KPXC_KEYS"); p != "" {
		return p
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "kpxc-client-keys.json"
	}
	return filepath.Join(cfg, "kpxc-client", "keys.json")
}

// LoadKeyStore reads (or creates) the key store.
func LoadKeyStore() (*KeyStore, error) {
	p := keyStorePath()
	ks := &KeyStore{path: p, Databases: map[string]StoredKey{}}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return ks, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, ks); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", p, err)
	}
	if ks.Databases == nil {
		ks.Databases = map[string]StoredKey{}
	}
	return ks, nil
}

// Save writes the key store with 0600 permissions.
func (ks *KeyStore) Save() error {
	if err := os.MkdirAll(filepath.Dir(ks.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ks.path, data, 0o600)
}

// NewIdentity generates a fresh identification key pair.
func NewIdentity() (pubB64, privB64 string, err error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub[:]),
		base64.StdEncoding.EncodeToString(priv[:]), nil
}

// identity holds the session keys used for associate/test-associate.
type identity struct {
	dbHash    string
	id        string
	idPubB64  string
	idPrivB64 string
	known     bool
}

// associate performs association with the currently unlocked database.
// On success the identity is stored in the key store.
func associate(c *Client, ks *KeyStore) (*identity, error) {
	dbHash, err := databaseHash(c)
	if err != nil {
		return nil, err
	}
	if sk, ok := ks.Databases[dbHash]; ok {
		id := &identity{dbHash: dbHash, id: sk.ID, idPubB64: sk.PublicKey, idPrivB64: sk.SecretKey, known: true}
		if err := testAssociate(c, id); err == nil {
			return id, nil
		}
	}
	pubB64, privB64, err := NewIdentity()
	if err != nil {
		return nil, err
	}
	// "key" must be the session public key from change-public-keys;
	// "idKey" is the permanent identification key stored in the database.
	sessionPubB64 := base64.StdEncoding.EncodeToString(c.clientPub[:])
	resp, err := c.request("associate", map[string]any{
		"key":   sessionPubB64,
		"idKey": pubB64,
	})
	if err != nil {
		return nil, fmt.Errorf("association rejected: %w", err)
	}
	var out struct {
		ID      string   `json:"id"`
		Success flexBool `json:"success"`
	}
	if err := json.Unmarshal(resp, &out); err != nil || !out.Success || out.ID == "" {
		return nil, fmt.Errorf("association failed")
	}
	id := &identity{dbHash: dbHash, id: out.ID, idPubB64: pubB64, idPrivB64: privB64, known: true}
	ks.Databases[dbHash] = StoredKey{ID: out.ID, PublicKey: pubB64, SecretKey: privB64}
	if err := ks.Save(); err != nil {
		return nil, err
	}
	return id, nil
}

// testAssociate checks an existing identity.
func testAssociate(c *Client, id *identity) error {
	_, err := c.request("test-associate", map[string]any{
		"id":  id.id,
		"key": id.idPubB64,
	})
	return err
}

func databaseHash(c *Client) (string, error) {
	resp, err := c.request("get-databasehash", nil)
	if err != nil {
		return "", err
	}
	var out struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(resp, &out); err != nil || out.Hash == "" {
		return "", fmt.Errorf("no database hash in response")
	}
	return out.Hash, nil
}
