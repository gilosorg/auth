package database

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"gilosauth/config"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// DB is the global database connection
var DB *gorm.DB

// buildSQLiteDSN attaches critical per-connection PRAGMAs via DSN query parameters
// so every pooled SQLite handle starts with foreign keys and busy_timeout enabled.
func buildSQLiteDSN(dbPath string) string {
	if dbPath == "" || dbPath == ":memory:" {
		return dbPath
	}
	params := "_foreign_keys=on&_busy_timeout=5000&_journal_mode=WAL&_synchronous=NORMAL&_secure_delete=on"
	if strings.Contains(dbPath, "?") {
		return dbPath + "&" + params
	}
	return dbPath + "?" + params
}

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
	DB, err = gorm.Open(sqlite.Open(buildSQLiteDSN(config.DBPath)), &gorm.Config{})
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
