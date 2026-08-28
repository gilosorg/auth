package database

import (
	"fmt"
	"log"
)

// MigrateDatabase runs auto-migration for all models.
func MigrateDatabase() error {
	if DB == nil {
		return fmt.Errorf("database connection is not initialized")
	}

	sqlDB, err := DB.DB()
	if err == nil {
		// Temporarily disable foreign keys for migration to allow SQLite table rebuilds
		sqlDB.Exec("PRAGMA foreign_keys=OFF")
		defer sqlDB.Exec("PRAGMA foreign_keys=ON")
	}

	err = DB.AutoMigrate(
		&User{},
		&Client{},
		&Session{},
		&TOTPSecret{},
		&SecurityBlock{},
		&UsernameChangeLog{},
		&AuditLog{},
		&AccountDeletionRequest{},
	)
	if err != nil {
		log.Printf("Failed to auto-migrate models: %v", err)
		return fmt.Errorf("failed to auto-migrate models: %w", err)
	}

	log.Println("Models auto-migrated successfully")
	return nil
}
