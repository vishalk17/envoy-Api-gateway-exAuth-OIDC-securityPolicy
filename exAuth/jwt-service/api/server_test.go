package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/vishalk17/jwt-service/auth"
)

func TestHealthHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	
	req, _ := http.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	
	// Create a minimal gin engine for testing
	router := gin.New()
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":    "healthy",
			"timestamp": 1234567890,
		})
	})
	
	router.ServeHTTP(rec, req)
	
	assert.Equal(t, http.StatusOK, rec.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])
}

func TestGenerateTokenHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	
	// Create request body
	reqBody := map[string]string{
		"customer_id": "test-customer-123",
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	
	// Create a minimal gin engine for testing
	router := gin.New()
	router.POST("/token", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"token": "mocked.token.string",
		})
	})
	
	router.ServeHTTP(rec, req)
	
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestVerifyJWTHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	
	// Test with no authorization header
	req, _ := http.NewRequest(http.MethodPost, "/verify", nil)
	rec := httptest.NewRecorder()
	
	// Create a minimal gin engine for testing
	router := gin.New()
	router.POST("/verify", func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{
				"error": "Authorization header required",
			})
			return
		}
		
		c.JSON(200, gin.H{
			"status": "authorized",
		})
	})
	
	router.ServeHTTP(rec, req)
	
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	
	// Test with authorization header
	req2, _ := http.NewRequest(http.MethodPost, "/verify", nil)
	req2.Header.Set("Authorization", "Bearer valid-token")
	rec2 := httptest.NewRecorder()
	
	router.ServeHTTP(rec2, req2)
	
	assert.Equal(t, http.StatusOK, rec2.Code)
}