package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/time/rate"

	"kunuk.dev/core/internal/httpx"
)

// RateLimit limita le richieste per IP (difesa in profondità: il grosso del rate limiting lo
// fa Caddy, doc 07/21). `every` = cadenza dei token, `burst` = picco. Su superamento → 429
// con Retry-After. TODO(0.9.x): cap/cleanup della mappa per IP (crescita non limitata).
func RateLimit(every rate.Limit, burst int) func(http.Handler) http.Handler {
	l := &ipLimiter{m: make(map[string]*rate.Limiter), every: every, burst: burst}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.get(clientIP(r)).Allow() {
				w.Header().Set("Retry-After", "1")
				httpx.WriteError(w, r, httpx.CodeRateLimited, "troppe richieste")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type ipLimiter struct {
	mu    sync.Mutex
	m     map[string]*rate.Limiter
	every rate.Limit
	burst int
}

func (l *ipLimiter) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.m[ip]
	if !ok {
		lim = rate.NewLimiter(l.every, l.burst)
		l.m[ip] = lim
	}
	return lim
}

// clientIP preferisce X-Forwarded-For (impostato da Caddy, unico ingress) e ricade su
// RemoteAddr. Dietro a Caddy l'XFF è attendibile; non esposto direttamente a Internet.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
