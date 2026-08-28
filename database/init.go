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
	sqlDB.Exec("PRAGMA journal_mode=WAL")
	sqlDB.Exec("PRAGMA foreign_keys=ON")
	sqlDB.Exec("PRAGMA busy_timeout=5000")
	sqlDB.Exec("PRAGMA secure_delete=ON")       // Zero-fill deleted data for security
	sqlDB.Exec("PRAGMA auto_vacuum=INCREMENTAL") // Reclaim space after deletions
	sqlDB.Exec("PRAGMA synchronous=NORMAL")      // Safe for WAL mode, better performance than FULL

	// Connection pool settings — SQLite supports only one concurrent writer.
	// A single open connection with WAL mode provides the best concurrency:
	// one writer + unlimited readers without SQLITE_BUSY errors.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0) // Don't close the single connection

	log.Println("Database connected successfully")
}
