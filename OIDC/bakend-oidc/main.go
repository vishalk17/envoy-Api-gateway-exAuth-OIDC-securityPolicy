package main

import (
    "fmt"
    "log"
    "net/http"
)

func main() {
    fmt.Println("Starting backend...")

    if err := initDB(); err != nil {
        log.Fatalf("Database connection failed: %v", err)
    }

    http.HandleFunc("/", userHandler)
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("OK\n"))
    })

    fmt.Println("Server running on :80")
    log.Fatal(http.ListenAndServe(":80", nil))
}
