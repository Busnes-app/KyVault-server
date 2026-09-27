package main

import (
	"github.com/Busnes-app/kyvault-server/internal/backup"
	"testing"
	"time"
)

func TestBackupDepositInterval(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
		bad   bool
	}{
		{"", 24 * time.Hour, false},
		{"0", 0, false},
		{"15m", 15 * time.Minute, false},
		{"1h", time.Hour, false},
		{"14m59s", 0, true},
		{"-1h", 0, true},
		{"tomorrow", 0, true},
		{"900.5s", 0, true},
		{"9000h", 0, true},
	}
	for _, test := range tests {
		t.Setenv("KYVAULT_BACKUP_DEPOSIT_INTERVAL", test.value)
		cfg, err := backup.ConfigFromEnv()
		got := cfg.Interval
		if (err != nil) != test.bad || !test.bad && got != test.want {
			t.Errorf("backupDepositInterval(%q) = %s, %v", test.value, got, err)
		}
	}
}

func TestInstanceLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := acquireInstanceLock(dir); err == nil {
		second.Close()
		t.Fatal("second instance lock succeeded")
	}
}

func TestParseTrustedProxies(t *testing.T) {
	got, err := parseTrustedProxies(" 10.0.0.1, 172.16.0.0/12 ,2001:db8::1 ")
	if err != nil || len(got) != 3 || got[0].String() != "10.0.0.1/32" || got[1].String() != "172.16.0.0/12" || got[2].String() != "2001:db8::1/128" {
		t.Fatalf("parse = %v, %v", got, err)
	}
	if got, err := parseTrustedProxies(""); err != nil || len(got) != 0 {
		t.Fatalf("empty = %v, %v", got, err)
	}
	if _, err := parseTrustedProxies("proxy.local"); err == nil {
		t.Fatal("a hostname must be refused")
	}
}
