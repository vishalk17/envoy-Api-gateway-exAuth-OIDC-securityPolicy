package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vishalk17/jwt-service/auth"
	"github.com/vishalk17/jwt-service/db"
	"github.com/vishalk17/jwt-service/models"
)

var (
	databaseURL string
	customerID  string
	accountID   string
	expiration  int
	minutes     int
	token       string
)

var rootCmd = &cobra.Command{
	Use:   "jwt-service",
	Short: "JWT Service CLI for customer management and token generation",
	Long:  `A command-line interface for managing JWT customers and generating tokens.`,
}

var createCustomerCmd = &cobra.Command{
	Use:   "customer-create",
	Short: "Create a new customer with a secret key",
	Long:  `Creates a new customer entry with a randomly generated secret key.`,
	Run: func(cmd *cobra.Command, args []string) {
		database, err := db.NewDatabase(databaseURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to database: %v\n", err)
			os.Exit(1)
		}
		defer database.Close()

		// Generate a secret key for the customer
		secretKey, err := auth.GenerateSecretKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate secret key: %v\n", err)
			os.Exit(1)
		}

		customer := &models.Customer{
			CustomerID:        customerID,
			AccountID:         accountID,
			SecretKey:         secretKey,
			ExpirationMinutes: expiration,
		}

		if err := database.CreateCustomer(customer); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create customer: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Customer created successfully:\n")
		fmt.Printf("  ID: %d\n", customer.ID)
		fmt.Printf("  Customer ID: %s\n", customer.CustomerID)
		fmt.Printf("  Account ID: %s\n", customer.AccountID)
		fmt.Printf("  Expiration Minutes: %d\n", customer.ExpirationMinutes)
		fmt.Printf("  Created At: %s\n", customer.CreatedAt.Format(time.RFC3339))
	},
}

var listCustomersCmd = &cobra.Command{
	Use:   "customer-list",
	Short: "List all customers",
	Long:  `Lists all customers in the database.`,
	Run: func(cmd *cobra.Command, args []string) {
		database, err := db.NewDatabase(databaseURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to database: %v\n", err)
			os.Exit(1)
		}
		defer database.Close()

		customers, err := database.ListCustomers()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list customers: %v\n", err)
			os.Exit(1)
		}

		if len(customers) == 0 {
			fmt.Println("No customers found.")
			return
		}

		fmt.Printf("%-5s %-20s %-20s %-10s %-20s\n", "ID", "Customer ID", "Account ID", "Exp (min)", "Created At")
		fmt.Println(strings.Repeat("-", 80))
		for _, customer := range customers {
			fmt.Printf("%-5d %-20s %-20s %-10d %-20s\n",
				customer.ID,
				customer.CustomerID,
				customer.AccountID,
				customer.ExpirationMinutes,
				customer.CreatedAt.Format("2006-01-02 15:04:05"))
		}
	},
}

var generateTokenCmd = &cobra.Command{
	Use:   "jwt-generate",
	Short: "Generate a JWT token for a customer",
	Long:  `Generates a JWT token for the specified customer with the specified expiration time.`,
	Run: func(cmd *cobra.Command, args []string) {
		database, err := db.NewDatabase(databaseURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to database: %v\n", err)
			os.Exit(1)
		}
		defer database.Close()

		jwtService := auth.NewJWTService(database)
		token, err := jwtService.CreateCustomerJWT(customerID, minutes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create JWT: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("JWT Token generated:\n%s\n", token)
	},
}

var verifyTokenCmd = &cobra.Command{
	Use:   "jwt-verify",
	Short: "Verify a JWT token",
	Long:  `Verifies a JWT token using the customer's secret key from the database.`,
	Run: func(cmd *cobra.Command, args []string) {
		database, err := db.NewDatabase(databaseURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to database: %v\n", err)
			os.Exit(1)
		}
		defer database.Close()

		jwtService := auth.NewJWTService(database)
		payload, err := jwtService.VerifyToken(token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Token verification failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Token verified successfully:\n")
		fmt.Printf("  Customer ID: %s\n", payload.CustomerID)
		fmt.Printf("  Account ID: %s\n", payload.AccountID)
		fmt.Printf("  User ID: %s\n", payload.UserID)
		fmt.Printf("  Expiration: %s\n", time.Unix(payload.Exp, 0).Format(time.RFC3339))
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&databaseURL, "db-url", "postgres://postgres:password@localhost:5432/jwt_service?sslmode=disable", "Database connection URL")

	// Customer create flags
	createCustomerCmd.Flags().StringVar(&customerID, "customer-id", "", "Customer ID (required)")
	createCustomerCmd.Flags().StringVar(&accountID, "account-id", "", "Account ID (required)")
	createCustomerCmd.Flags().IntVar(&expiration, "expiration", 60, "Expiration time in minutes")
	createCustomerCmd.MarkFlagRequired("customer-id")
	createCustomerCmd.MarkFlagRequired("account-id")

	// JWT generate flags
	generateTokenCmd.Flags().StringVar(&customerID, "customer-id", "", "Customer ID (required)")
	generateTokenCmd.Flags().IntVar(&minutes, "minutes", 60, "Expiration time in minutes")
	generateTokenCmd.MarkFlagRequired("customer-id")

	// JWT verify flags
	verifyTokenCmd.Flags().StringVar(&token, "token", "", "JWT token to verify (required)")
	verifyTokenCmd.MarkFlagRequired("token")

	// Add commands to root
	rootCmd.AddCommand(createCustomerCmd)
	rootCmd.AddCommand(listCustomersCmd)
	rootCmd.AddCommand(generateTokenCmd)
	rootCmd.AddCommand(verifyTokenCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}