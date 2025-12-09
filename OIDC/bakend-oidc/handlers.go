package main

import (
    "fmt"
    "net/http"
)

func userHandler(w http.ResponseWriter, r *http.Request) {

    idToken, err := extractIDToken(r)
    if err != nil {
        http.Error(w, "Unauthorized: No ID token", http.StatusUnauthorized)
        return
    }

    claims, err := parseIDToken(idToken)
    if err != nil {
        http.Error(w, "Invalid JWT token", http.StatusUnauthorized)
        return
    }

    email := claims["email"].(string)

    user, err := getUserByEmail(email)
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }

    if user == nil {
        fmt.Fprintf(w, "User %s not found. Please sign up.\n", email)
        return
    }

    fmt.Fprintf(w,
        "Welcome %s!\nEmail: %s\nLocation: %s\nCountry: %s\n",
        user.Name, email, user.Location, user.Country,
    )
}
