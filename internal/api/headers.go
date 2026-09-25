package api

import "net/http"

// contentSecurityPolicy is the strictest policy the built frontend runs under.
// 'wasm-unsafe-eval' is for hash-wasm (Argon2). data: and blob: images are the pairing
// QR code. Inline React style props go through CSSOM and are not governed by style-src.
const contentSecurityPolicy = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; " +
	"style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"

// SecurityHeaders applies browser hardening to every response, API and static alike.
// There is no CORS: the web app is same-origin and native clients use Bearer tokens
// from a non-browser context, which CORS does not gate. Browser extensions reach the
// API through their host permissions, which also bypass CORS.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000") // ignored by browsers over plain HTTP
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}
