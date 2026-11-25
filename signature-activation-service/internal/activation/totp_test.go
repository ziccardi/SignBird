package activation

import (
	"testing"
	"time"
)

func TestTOTPVectorAndReplay(t *testing.T) {
	seed := []byte("12345678901234567890")
	now := time.Unix(59, 0)
	counter, ok := matchOTP(seed, "287082", now, -1)
	if !ok || counter != 1 {
		t.Fatalf("RFC 6238 vector was rejected: %d", counter)
	}
	if _, ok := matchOTP(seed, "287082", now, counter); ok {
		t.Fatal("replayed code was accepted")
	}
	if _, ok := matchOTP(seed, "287082", now.Add(90*time.Second), -1); ok {
		t.Fatal("expired code was accepted")
	}
}
