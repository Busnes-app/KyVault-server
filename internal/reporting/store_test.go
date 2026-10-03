package reporting

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestDurableAtomicGenerationAndExpiry(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	var gen string
	if err = s.Access(func(st *State) (bool, error) {
		st.Configure(Config{Enabled: true, RecipientID: "admin"})
		gen = st.Config.Generation
		st.Records["u"] = Record{Generation: gen, ReceivedAt: time.Now(), Sealed: "opaque"}
		st.Records["expired"] = Record{Generation: gen, ReceivedAt: time.Now().Add(-Retention - time.Second)}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Access(func(st *State) (bool, error) {
		if len(st.Records) != 1 || st.Records["u"].Sealed != "opaque" {
			t.Fatal(st.Records)
		}
		return false, nil
	})
	if err = os.Mkdir(filepath.Join(dir, "state.json.tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = loaded.Access(func(st *State) (bool, error) { st.Configure(Config{}); return true, nil }); err == nil {
		t.Fatal("acknowledged failed persistence")
	}
	loaded.Access(func(st *State) (bool, error) {
		if st.Config.Generation != gen || len(st.Records) != 1 {
			t.Fatal("failed write changed memory")
		}
		return false, nil
	})
	os.Remove(filepath.Join(dir, "state.json.tmp"))
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := loaded.Access(func(st *State) (bool, error) {
				st.Configure(Config{Enabled: true})
				st.Records["u"] = Record{Generation: st.Config.Generation, ReceivedAt: time.Now()}
				return true, nil
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	loaded.Access(func(st *State) (bool, error) {
		if st.Records["u"].Generation != st.Config.Generation {
			t.Fatal("generation crossed")
		}
		return false, nil
	})
	info, _ := os.Stat(filepath.Join(dir, "state.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
}
