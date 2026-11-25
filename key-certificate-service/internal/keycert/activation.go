package keycert

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"time"
)

var totpCode = regexp.MustCompile("^[0-9]{6}$")

func (s *service) authorizeChange(w http.ResponseWriter, r *http.Request) bool {
	if s.consumeCode == nil {
		fail(w, http.StatusServiceUnavailable, "Signature activation is unavailable")
		return false
	}
	return s.consumeCode(w, r)
}

func otpConsumer(token string) func(http.ResponseWriter, *http.Request) bool {
	client := &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return func(w http.ResponseWriter, r *http.Request) bool {
		values := r.Header.Values("X-TOTP-Code")
		if len(values) != 1 || !totpCode.MatchString(values[0]) {
			fail(w, http.StatusBadRequest, "A six-digit X-TOTP-Code is required")
			return false
		}
		body, _ := json.Marshal(map[string]string{"code": values[0]})
		request, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
			"http://127.0.0.1:8082/internal/activation/totp/consume", bytes.NewReader(body))
		if err != nil {
			internalError(w, err)
			return false
		}
		request.Header.Set("Authorization", r.Header.Get("Authorization"))
		request.Header.Set("X-SignBird-Service-Token", token)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			fail(w, http.StatusServiceUnavailable, "Signature activation is unavailable")
			return false
		}
		defer response.Body.Close()
		switch response.StatusCode {
		case http.StatusOK:
			return true
		case http.StatusBadRequest, http.StatusConflict, http.StatusTooManyRequests:
			var failure struct{ Message string }
			if json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&failure) == nil {
				fail(w, response.StatusCode, failure.Message)
				return false
			}
		}
		fail(w, http.StatusServiceUnavailable, "Signature activation is unavailable")
		return false
	}
}
