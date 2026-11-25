package activation

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

func otp(seed []byte, counter int64) string {
	var input [8]byte
	binary.BigEndian.PutUint64(input[:], uint64(counter))
	mac := hmac.New(sha1.New, seed)
	mac.Write(input[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

func matchOTP(seed []byte, code string, now time.Time, last int64) (int64, bool) {
	counter := now.Unix() / 30
	for candidate := counter + 1; candidate >= counter-1; candidate-- {
		if candidate > last && subtle.ConstantTimeCompare([]byte(otp(seed, candidate)), []byte(code)) == 1 {
			return candidate, true
		}
	}
	return 0, false
}
