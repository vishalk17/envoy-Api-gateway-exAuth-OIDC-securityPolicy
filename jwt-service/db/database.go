package db

import (
    "database/sql"

    _ "github.com/lib/pq"
    "github.com/vishalk17/jwt-service/models"
)

type Database struct {
    DB *sql.DB
}

func NewDatabase(connectionString string) (*Database, error) {
    db, err := sql.Open("postgres", connectionString)
    if err != nil {
        return nil, err
    }

    if err = db.Ping(); err != nil {
        return nil, err
    }

    // Create customers table if it doesn't exist
    createTableQuery := `
        CREATE TABLE IF NOT EXISTS customers (
            id SERIAL PRIMARY KEY,
            customer_id VARCHAR(255) UNIQUE NOT NULL,
            account_id VARCHAR(255) UNIQUE NOT NULL,
            secret_key TEXT NOT NULL,
            expiration_minutes INTEGER DEFAULT 60,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `

    if _, err = db.Exec(createTableQuery); err != nil {
        return nil, err
    }

    return &Database{DB: db}, nil
}

func (d *Database) CreateCustomer(customer *models.Customer) error {
    query := `
        INSERT INTO customers (customer_id, account_id, secret_key, expiration_minutes) 
        VALUES ($1, $2, $3, $4) 
        RETURNING id, created_at, updated_at
    `
    
    err := d.DB.QueryRow(query, 
        customer.CustomerID, 
        customer.AccountID, 
        customer.SecretKey, 
        customer.ExpirationMinutes,
    ).Scan(&customer.ID, &customer.CreatedAt, &customer.UpdatedAt)
    
    return err
}

func (d *Database) GetCustomerByID(customerID string) (*models.Customer, error) {
    query := `SELECT id, customer_id, account_id, expiration_minutes, created_at, updated_at FROM customers WHERE customer_id = $1`
    
    customer := &models.Customer{}
    err := d.DB.QueryRow(query, customerID).Scan(
        &customer.ID,
        &customer.CustomerID,
        &customer.AccountID,
        &customer.ExpirationMinutes,
        &customer.CreatedAt,
        &customer.UpdatedAt,
    )
    
    if err != nil {
        return nil, err
    }
    
    return customer, nil
}

func (d *Database) GetSecretKeyForCustomer(customerID string) (string, error) {
    query := `SELECT secret_key FROM customers WHERE customer_id = $1`
    
    var secretKey string
    err := d.DB.QueryRow(query, customerID).Scan(&secretKey)
    
    return secretKey, err
}

func (d *Database) ListCustomers() ([]*models.Customer, error) {
    query := `SELECT id, customer_id, account_id, expiration_minutes, created_at, updated_at FROM customers ORDER BY created_at DESC`
    
    rows, err := d.DB.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var customers []*models.Customer
    for rows.Next() {
        customer := &models.Customer{}
        if err := rows.Scan(
            &customer.ID,
            &customer.CustomerID,
            &customer.AccountID,
            &customer.ExpirationMinutes,
            &customer.CreatedAt,
            &customer.UpdatedAt,
        ); err != nil {
            return nil, err
        }
        customers = append(customers, customer)
    }
    
    return customers, nil
}

func (d *Database) UpdateCustomer(customer *models.Customer) error {
    query := `
        UPDATE customers 
        SET account_id = $2, expiration_minutes = $3, updated_at = CURRENT_TIMESTAMP
        WHERE customer_id = $1
    `
    
    _, err := d.DB.Exec(query, 
        customer.CustomerID, 
        customer.AccountID, 
        customer.ExpirationMinutes,
    )
    
    return err
}

func (d *Database) DeleteCustomer(customerID string) error {
    query := `DELETE FROM customers WHERE customer_id = $1`
    
    _, err := d.DB.Exec(query, customerID)
    
    return err
}

func (d *Database) Close() {
    if d.DB != nil {
        d.DB.Close()
    }
}