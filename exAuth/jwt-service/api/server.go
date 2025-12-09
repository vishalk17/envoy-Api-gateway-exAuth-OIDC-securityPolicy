package api

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vishalk17/jwt-service/auth"
	"github.com/vishalk17/jwt-service/db"
)

type Server struct {
	engine    *gin.Engine
	jwtService *auth.JWTService
}

func StartServer() {
	// Set up gin
	gin.SetMode(gin.ReleaseMode)

	// Get database URL from environment or use default
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:password@localhost:5432/jwt_service?sslmode=disable"
	}

	// Connect to database
	database, err := db.NewDatabase(dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Create JWT service
	jwtService := auth.NewJWTService(database)

	// Create server
	server := &Server{
		engine:     gin.New(),
		jwtService: jwtService,
	}

	// Setup routes
	server.setupRoutes()

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	if err := server.engine.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func (s *Server) setupRoutes() {
	// Middleware
	s.engine.Use(gin.Logger())
	s.engine.Use(gin.Recovery())

	// Health check endpoint
	s.engine.GET("/health", s.healthHandler)

	// Handle POST requests at root for JWT verification
	s.engine.POST("/", s.verifyJWTHandler)

	// CLI endpoints for token generation (if needed externally)
	s.engine.POST("/token", s.generateTokenHandler)
}

func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
	})
}

func (s *Server) verifyJWTHandler(c *gin.Context) {
	// Check for logging level to determine detail level
	logLevel := os.Getenv("LOG_LEVEL")
	
	// Log basic incoming request details
	log.Printf("Incoming /verify request - Method: %s, Path: %s, IP: %s", c.Request.Method, c.Request.URL.Path, c.ClientIP())
	
	// Log headers only if detailed logging is enabled
	if logLevel == "DEBUG" {
		log.Printf("Request Headers:")
		for key, values := range c.Request.Header {
			for _, value := range values {
				if key == "Authorization" {
					log.Printf("  %s: [REDACTED - Bearer token present]", key)
				} else {
					log.Printf("  %s: %s", key, value)
				}
			}
		}
	} else {
		log.Printf("Request contains Authorization header: %t", c.GetHeader("Authorization") != "")
	}

	// Extract token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		log.Printf("No Authorization header found in request")
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Authorization header required",
		})
		return
	}

	if logLevel == "DEBUG" {
		log.Printf("Authorization header found: %s", authHeader)
	} else {
		log.Printf("Authorization header found with Bearer token")
	}

	// Handle both "Bearer <token>" and raw token formats
	token := authHeader
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
		if logLevel == "DEBUG" {
			log.Printf("Extracted token from Bearer format: %s", token[:min(20, len(token))]+"...")
		} else {
			log.Printf("Extracted token from Bearer format")
		}
	} else {
		if logLevel == "DEBUG" {
			log.Printf("Using raw token format: %s", token[:min(20, len(token))]+"...")
		} else {
			log.Printf("Using raw token format")
		}
	}

	// Log token details before verification (only non-sensitive details)
	if logLevel == "DEBUG" {
		log.Printf("Starting token verification for token: %s", token[:min(20, len(token))]+"...")
	} else {
		log.Printf("Starting token verification")
	}

	// Verify the token
	payload, err := s.jwtService.VerifyToken(token)
	if err != nil {
		log.Printf("Token verification failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
		})
		log.Printf("Sending 401 response to caller")
		return
	}

	log.Printf("Token verification successful - Customer ID: %s, Account ID: %s, User ID: %s", 
		payload.CustomerID, payload.AccountID, payload.UserID)

	// For Envoy external auth, a 200 status means "allow the request"
	// Add authentication details as headers that will be passed to the backend service
	// These headers are added BEFORE the response body to ensure Envoy can see them
	c.Header("X-Customer-ID", payload.CustomerID)
	if payload.AccountID != "" {
		c.Header("X-Account-ID", payload.AccountID)
	}
	if payload.UserID != "" {
		c.Header("X-User-ID", payload.UserID)
	}
	
	// Additional headers that could be useful for the backend
	c.Header("X-Token-Verified", "true")
	c.Header("X-Token-Expiration", time.Unix(payload.Exp, 0).Format(time.RFC3339))
	
	// For better observability, log the headers that will be forwarded
	log.Printf("Forwarding headers to backend - X-Customer-ID: %s, X-Account-ID: %s, X-User-ID: %s", 
		payload.CustomerID, payload.AccountID, payload.UserID)

	// Create response
	response := gin.H{
		"status": "authorized",
		"customer_id": payload.CustomerID,
		"account_id":  payload.AccountID,
		"user_id": payload.UserID,
		"expires_at":  time.Unix(payload.Exp, 0).Format(time.RFC3339),
	}
	
	if logLevel == "DEBUG" {
		log.Printf("Sending 200 response with payload: %+v", response)
	} else {
		log.Printf("Sending 200 response to caller")
	}
	c.JSON(http.StatusOK, response)
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *Server) generateTokenHandler(c *gin.Context) {
	var req struct {
		CustomerID string `json:"customer_id" binding:"required"`
		Minutes    *int   `json:"minutes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Invalid request body: %v", err),
		})
		return
	}

	// Default to 60 minutes if not specified
	minutes := 60
	if req.Minutes != nil {
		minutes = *req.Minutes
	}

	// Generate the token
	token, err := s.jwtService.CreateCustomerJWT(req.CustomerID, minutes)
	if err != nil {
		log.Printf("Token generation failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to generate token: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"expires_in_minutes": minutes,
	})
}