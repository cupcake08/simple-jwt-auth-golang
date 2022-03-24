package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/login", Login)
	http.HandleFunc("/home", Home)
	http.HandleFunc("/refresh", Refresh)

	//we are not using any router so put nil as router argument
	log.Fatal(http.ListenAndServe(":8080", nil))
}
