// Package pid implements daemon singletons via pid file + flock.
//
// The lock — not the file — arbitrates: it dies with the process, so
// crashes, kills, and container recreations (stale files on volumes)
// can never wedge startup. The pid inside is advisory only, for humans
// (`already running (pid N)`) and signals (down/status).
package pid

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Lock is a held pid-file lock; Close releases it and removes the file.
type Lock struct {
	f    *os.File
	path string
}

// Close releases the lock and removes the pid file.
func (l *Lock) Close() {
	if l == nil || l.f == nil {
		return
	}
	l.f.Close()
	os.Remove(l.path)
}

// Acquire takes an exclusive non-blocking flock on path, records pid, and
// holds it for the caller's lifetime. A live holder errors naming its pid;
// anything else (absent/stale/dead) proceeds.
func Acquire(path string, pid int, want string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if old := Read(path); Live(old, want) {
			return nil, fmt.Errorf("daemon already running (pid %d) — stop it first", old)
		}
		return nil, fmt.Errorf("daemon lock busy — stop it first")
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := fmt.Fprintf(f, "%d", pid); err != nil {
		f.Close()
		return nil, err
	}
	return &Lock{f: f, path: path}, nil
}

// Busy reports whether path is currently flock-held (advisory pre-check;
// the lock in Acquire is the arbiter).
func Busy(path string) bool {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil
}

// Read parses the pid file (-1 when absent/unparsable).
func Read(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	var pid int
	if _, err := fmt.Sscanf(string(b), "%d", &pid); err != nil || pid <= 0 {
		return -1
	}
	return pid
}

// Live reports whether pid is a running process named want. The /proc
// cmdline check (linux) guards against signaling a recycled PID; elsewhere
// signal-0 existence is the fallback.
func Live(pid int, want string) bool {
	if pid <= 0 {
		return false
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		parts := strings.Split(string(b), "\x00")
		if len(parts) == 0 || filepath.Base(parts[0]) != want {
			return false
		}
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
