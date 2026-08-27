package main

import (
	"encoding/json"
	"net/http"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]string{
		"status": "ok",
	}

	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/api/health", healthHandler)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
