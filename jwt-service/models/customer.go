package models

import "time"

type Customer struct {
    ID              int64     `json:"id"`
    CustomerID      string    `json:"customer_id"`
    AccountID       string    `json:"account_id"`
    SecretKey       string    `json:"-"` // Don't expose secret key in JSON
    ExpirationMinutes int     `json:"expiration_minutes"`
    CreatedAt       time.Time `json:"created_at"`
    UpdatedAt       time.Time `json:"updated_at"`
}

type JWTPayload struct {
    CustomerID string `json:"customer_id"`
    AccountID  string `json:"account_id"`
    UserID     string `json:"user_id,omitempty"`
    Exp        int64  `json:"exp"`
}