package pid

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireExclusive(t *testing.T) {
	path := t.TempDir() + "/d.pid"
	a, err := Acquire(path, os.Getpid(), "test")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer a.Close()
	if _, err := Acquire(path, os.Getpid(), "test"); err == nil {
		t.Fatal("second acquire succeeded while first held")
	}
	if !Busy(path) {
		t.Fatal("held lock reads idle")
	}
	a.Close()
	if Busy(path) {
		t.Fatal("released lock reads busy")
	}
	// Stale file, dead owner: must proceed, not wedge.
	b, err := Acquire(path, 999999999, "test")
	if err != nil {
		t.Fatalf("stale file blocked acquire: %v", err)
	}
	defer b.Close()
}

func TestLiveSelf(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no executable path")
	}
	if !Live(os.Getpid(), filepath.Base(exe)) {
		t.Fatal("own process not live")
	}
	if Live(999999999, "test") {
		t.Fatal("absurd pid live")
	}
	if _, err := os.ReadFile("/proc/self/cmdline"); err != nil {
		t.Skip("no /proc: cmdline guard untestable here")
	}
	if Live(os.Getpid(), "definitely-not-this-binary") {
		t.Fatal("wrong name matched")
	}
}
