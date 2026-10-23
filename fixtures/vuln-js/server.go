// INTENTIONALLY VULNERABLE TEST FIXTURE - never deploy
package main

import (
	"flag"
	"net/http"
)

func main() {
	addr := flag.String("addr", ":8787", "listen address")
	flag.Parse()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	})
	http.ListenAndServe(":8080", nil)
	_ = addr
}
