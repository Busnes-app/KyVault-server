// Package reporting stores an opaque, disposable client-report cache. It holds no keys.
package reporting

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const SealedBytes = 3184
const Retention = 7 * 24 * time.Hour

type Config struct {
	InstanceID    string `json:"instanceId"`
	Generation    string `json:"generation"`
	Enabled       bool   `json:"enabled"`
	RecipientID   string `json:"recipientId,omitempty"`
	RecipientName string `json:"recipientName,omitempty"`
	PublicKey     string `json:"publicKey,omitempty"`
	KeyDigest     string `json:"keyDigest,omitempty"`
}
type Record struct {
	InstanceID  string    `json:"instanceId"`
	Generation  string    `json:"generation"`
	SourceID    string    `json:"sourceId"`
	Version     int64     `json:"version"`
	ReportID    string    `json:"reportId"`
	RecipientID string    `json:"recipientId"`
	KeyDigest   string    `json:"keyDigest"`
	Sealed      string    `json:"sealed,omitempty"`
	ReceivedAt  time.Time `json:"receivedAt"`
}
type State struct {
	Config  Config            `json:"config"`
	Records map[string]Record `json:"records"`
}
type Store struct {
	mu    sync.Mutex
	path  string
	state State
}

func ID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json"), state: State{Config: Config{InstanceID: ID(), Generation: ID()}, Records: map[string]Record{}}}
	b, err := os.ReadFile(s.path)
	if err == nil {
		err = json.Unmarshal(b, &s.state)
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if s.state.Records == nil {
		s.state.Records = map[string]Record{}
	}
	// Access prunes before exposing anything, and saves initial state durably.
	err = s.Access(func(st *State) (bool, error) { return true, nil })
	return s, err
}

// Access serializes config/admission, clones before mutation, and commits only after
// persistence succeeds. One atomic file means invalidation and purge commit together.
// ponytail: O(users) clone/write; use per-record files with generation fencing if measured load requires it.
func (s *Store) Access(fn func(*State) (bool, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := State{Config: s.state.Config, Records: make(map[string]Record, len(s.state.Records))}
	dirty := false
	for id, r := range s.state.Records {
		if !next.Config.Enabled || r.Generation != next.Config.Generation || time.Since(r.ReceivedAt) > Retention {
			dirty = true
			continue
		}
		next.Records[id] = r
	}
	changed, err := fn(&next)
	if err != nil {
		return err
	}
	if !changed && !dirty {
		return nil
	}
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err = os.WriteFile(s.path+".tmp", b, 0600); err != nil {
		return err
	}
	if err = os.Rename(s.path+".tmp", s.path); err != nil {
		return err
	}
	s.state = next
	return nil
}
func (s *State) Configure(c Config) {
	c.InstanceID = s.Config.InstanceID
	c.Generation = ID()
	s.Config = c
	s.Records = map[string]Record{}
}
