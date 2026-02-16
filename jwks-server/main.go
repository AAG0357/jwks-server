package main

import (
	"log"
	"net/http"
)

func main() {
	srv, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Serving on http://localhost:8080")
	err = http.ListenAndServe(":8080", srv.routes())
	if err != nil {
		log.Fatal(err)
	}
}
