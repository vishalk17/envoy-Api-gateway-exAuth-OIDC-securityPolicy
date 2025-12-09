package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vishalk17/jwt-service/db"
	"github.com/vishalk17/jwt-service/models"
)

// IST timezone
var istLocation *time.Location

func init() {
	var err error
	istLocation, err = time.LoadLocation("Asia/Kolkata")
	if err != nil {
		istLocation = time.UTC // fallback to UTC if IST can't be loaded
	}
}

// Convert time to IST
func toIST(t time.Time) time.Time {
	return t.In(istLocation)
}

type JWTService struct {
	DB *db.Database
}

func NewJWTService(database *db.Database) *JWTService {
	return &JWTService{
		DB: database,
	}
}

// GenerateSecretKey creates a random 256-bit (32-byte) secret key
func GenerateSecretKey() (string, error) {
	key := make([]byte, 32) // 256-bit key for HS256
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// CreateCustomerJWT creates a JWT for a specific customer
func (j *JWTService) CreateCustomerJWT(customerID string, expirationMinutes int) (string, error) {
	// Get customer-specific secret key from database
	secretKey, err := j.DB.GetSecretKeyForCustomer(customerID)
	if err != nil {
		return "", fmt.Errorf("failed to get secret key for customer %s: %w", customerID, err)
	}

	expirationTime := toIST(time.Now()).Add(time.Duration(expirationMinutes) * time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"customerId": customerID,
		"exp":        expirationTime.Unix(),
		"iat":        toIST(time.Now()).Unix(),
	})

	// Sign the token with the customer-specific secret key
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// VerifyToken verifies a JWT token using the customer-specific secret key
func (j *JWTService) VerifyToken(tokenString string) (*models.JWTPayload, error) {
	// First, parse the token without verification to extract the customer ID
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract customer ID from unverified claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	customerID, ok := claims["customerId"].(string)
	if !ok {
		return nil, fmt.Errorf("customerId not found in token")
	}

	// Get the customer-specific secret key from database
	secretKey, err := j.DB.GetSecretKeyForCustomer(customerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret key for customer %s: %w", customerID, err)
	}

	// Now verify the token with the customer-specific key
	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Extract and validate claims after successful verification
	claims, ok = token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return nil, fmt.Errorf("token expired")
		}
	} else {
		return nil, fmt.Errorf("expiration not found in token")
	}

	// Create and return payload
	payload := &models.JWTPayload{
		CustomerID: customerID,
		Exp:        int64(claims["exp"].(float64)),
	}

	if accountID, ok := claims["accountId"].(string); ok {
		payload.AccountID = accountID
	}

	if userID, ok := claims["userId"].(string); ok {
		payload.UserID = userID
	}

	return payload, nil
}