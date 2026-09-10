package pair

import (
	"testing"
	"time"
)

func TestMintVerifyBurn(t *testing.T) {
	s := New(t.TempDir() + "/pair.db")
	now := time.Now()
	c, err := s.Mint(now)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Count(now); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
	if err := s.Verify(c, now.Add(time.Minute)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Single-use: second verify must fail with the identical error.
	if err := s.Verify(c, now.Add(2*time.Minute)); err != ErrInvalid {
		t.Fatalf("reuse err = %v, want ErrInvalid", err)
	}
}

func TestExpiryAndOracle(t *testing.T) {
	s := New(t.TempDir() + "/pair.db")
	now := time.Now()
	c, err := s.Mint(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(c, now.Add(TTL+time.Second)); err != ErrInvalid {
		t.Fatalf("expired err = %v, want ErrInvalid", err)
	}
	if err := s.Verify("pair-bogus", now); err != ErrInvalid {
		t.Fatalf("bogus err = %v, want ErrInvalid", err)
	}
}

func TestLock(t *testing.T) {
	s := New(t.TempDir() + "/pair.db")
	now := time.Now()
	c, err := s.Mint(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetLocked(true); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(c, now); err != ErrLocked {
		t.Fatalf("locked err = %v, want ErrLocked", err)
	}
	if _, err := s.Mint(now); err != ErrLocked {
		t.Fatalf("mint-while-locked err = %v, want ErrLocked", err)
	}
	if err := s.SetLocked(false); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(c, now); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
}
