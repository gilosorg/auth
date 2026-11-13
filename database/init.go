package database

import (
	"log"
	"os"
	"path/filepath"

	"gilosauth/config"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// DB is the global database connection
var DB *gorm.DB

// InitDatabase initializes the SQLite database connection
func InitDatabase() {
	var err error

	// Ensure the directory for the database file exists
	dbDir := filepath.Dir(config.DBPath)
	if dbDir != "." && dbDir != "" {
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			log.Fatalf("Failed to create database directory %s: %v", dbDir, err)
		}
	}

	// Connect to the database using GORM with SQLite
	DB, err = gorm.Open(sqlite.Open(config.DBPath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	// Enable WAL mode for better concurrent read performance
	sqlDB, err := DB.DB()
	if err != nil {
		log.Fatalf("Failed to get underlying sql.DB: %v", err)
	}
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA secure_delete=ON",
		"PRAGMA auto_vacuum=INCREMENTAL",
		"PRAGMA synchronous=NORMAL",
	}
	for _, pragma := range pragmas {
		if _, pErr := sqlDB.Exec(pragma); pErr != nil {
			log.Printf("WARNING: Failed to execute %s: %v", pragma, pErr)
		}
	}

	// Connection pool settings — SQLite supports only one concurrent writer.
	// A single open connection with WAL mode provides the best concurrency:
	// one writer + unlimited readers without SQLITE_BUSY errors.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0) // Don't close the single connection

	log.Println("Database connected successfully")
}
