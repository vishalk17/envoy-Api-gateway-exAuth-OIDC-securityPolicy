package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/vishalk17/jwt-service/models"
)

// Test the JWT payload extraction
func TestJWTPayloadExtraction(t *testing.T) {
	customerID := "test-customer-123"
	accountID := "test-account-456"
	userID := "test-user-789"
	
	// Create a sample payload
	payload := &models.JWTPayload{
		CustomerID: customerID,
		AccountID:  accountID,
		UserID:     userID,
		Exp:        time.Now().Add(1 * time.Hour).Unix(),
	}
	
	assert.Equal(t, customerID, payload.CustomerID)
	assert.Equal(t, accountID, payload.AccountID)
	assert.Equal(t, userID, payload.UserID)
}

// Test token creation and parsing with a known key
func TestTokenCreationParsing(t *testing.T) {
	secretKey := "test-secret-key-for-testing-purposes-only"
	customerID := "test-customer-999"
	
	// Create a token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"customerId": customerID,
		"exp":        time.Now().Add(1 * time.Hour).Unix(),
	})
	
	tokenString, err := token.SignedString([]byte(secretKey))
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)
	
	// Parse and verify the token
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	
	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid)
	
	// Extract claims
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		assert.Equal(t, customerID, claims["customerId"])
		assert.NotNil(t, claims["exp"])
	}
}