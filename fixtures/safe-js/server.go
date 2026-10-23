package main

import (
	"flag"
	"net/http"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address")
	flag.Parse()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
	})
	http.ListenAndServe(*addr, nil)
}
