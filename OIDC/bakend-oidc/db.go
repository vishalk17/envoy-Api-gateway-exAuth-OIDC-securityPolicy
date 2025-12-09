package main

import (
    "database/sql"

    _ "github.com/lib/pq"
)

var db *sql.DB

func initDB() error {
    var err error
    db, err = sql.Open("postgres",
        "postgres://postgres:mypassword@postgres:5432/usersdb?sslmode=disable")

    if err != nil {
        return err
    }

    return db.Ping()
}

type User struct {
    Name     string
    Location string
    Country  string
}

func getUserByEmail(email string) (*User, error) {
    query := "SELECT name, location, country FROM users WHERE email=$1"
    row := db.QueryRow(query, email)

    u := &User{}
    err := row.Scan(&u.Name, &u.Location, &u.Country)

    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }

    return u, nil
}
