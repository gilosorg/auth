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

	if err == nil && sqlDB != nil {
		// Replace legacy non-partial unique indexes so unset contacts and per-user TOTP UUIDs do not collide.
		for _, stmt := range []string{
			"DROP INDEX IF EXISTS idx_users_email",
			"DROP INDEX IF EXISTS idx_users_phone",
			"DROP INDEX IF EXISTS idx_totp_secrets_uuid",
		} {
			if _, dropErr := sqlDB.Exec(stmt); dropErr != nil {
				log.Printf("WARNING: Failed to execute migration index cleanup (%s): %v", stmt, dropErr)
			}
		}
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

	if sqlDB, dbErr := DB.DB(); dbErr == nil {
		for _, stmt := range []string{
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email) WHERE email != ''",
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone_unique ON users(phone) WHERE phone != 0",
			"CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",
			"CREATE INDEX IF NOT EXISTS idx_sessions_user_type ON sessions(user_id, type)",
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_account_deletion_pending_user ON account_deletion_requests(user_id) WHERE status = 'pending'",
		} {
			if _, idxErr := sqlDB.Exec(stmt); idxErr != nil {
				return fmt.Errorf("failed to ensure index (%s): %w", stmt, idxErr)
			}
		}
	}

	log.Println("Models auto-migrated successfully")
	return nil
}
