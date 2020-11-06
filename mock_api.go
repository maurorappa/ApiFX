package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	logger := log.New(os.Stdout, "http: ", log.LstdFlags)
	server := &http.Server{
		Addr:         ":8080",
		Handler:      routes(),
		ErrorLog:     logger,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}
	server.ListenAndServe()
	for {

	}
}

func routes() *http.ServeMux {
	router := http.NewServeMux()
	router.HandleFunc("/accounts", accounts)
	return router
}

func accounts(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to the Test API server")
}
