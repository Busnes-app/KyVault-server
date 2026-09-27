package api

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type SharedSettings struct {
	CreateRestrictedToAdmins bool `json:"createRestrictedToAdmins"`
}

// sharedSettings is CONFIG_DIR/shared.json; absent means defaults.
type sharedSettings struct {
	path string
	mu   sync.Mutex
}

func newSharedSettings(configDir string) *sharedSettings {
	return &sharedSettings{path: filepath.Join(configDir, "shared.json")}
}

func (c *sharedSettings) Get() (SharedSettings, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var v SharedSettings
	data, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	return v, json.Unmarshal(data, &v)
}

func (c *sharedSettings) Put(v SharedSettings) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
