package main

import (
    "errors"
    "net/http"
    "strings"

    "github.com/golang-jwt/jwt/v5"
)

func extractIDToken(r *http.Request) (string, error) {
    // Find cookie with ID token
    for _, c := range r.Cookies() {
        if strings.HasPrefix(c.Name, "IdToken") {
            return c.Value, nil
        }
    }
    return "", errors.New("ID token not found in cookies")
}

func parseIDToken(tokenStr string) (jwt.MapClaims, error) {
    token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
    if err != nil {
        return nil, err
    }
    return token.Claims.(jwt.MapClaims), nil
}
