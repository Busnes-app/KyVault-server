package api

import (
	"net/http"
	"os"
	"path/filepath"
)

// SPAHandler serves the built frontend. Every directory and every unknown path gets
// index.html so the client router can take over; http.FileServer's directory listing
// is never reachable.
func SPAHandler(webDir string) http.Handler {
	files := http.FileServer(http.Dir(webDir))
	index := filepath.Join(webDir, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := filepath.Join(webDir, filepath.Clean("/"+r.URL.Path))
		info, err := os.Stat(target)
		if err != nil || info.IsDir() {
			http.ServeFile(w, r, index)
			return
		}
		files.ServeHTTP(w, r)
	})
}
