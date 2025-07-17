package database

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"reconcli-webui/internal/config"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type User struct {
	ID        uint      `json:"id" gorm:"primarykey"`
	Username  string    `json:"username" gorm:"unique;not null"`
	Email     string    `json:"email" gorm:"unique;not null"`
	Password  string    `json:"-" gorm:"not null"`
	Role      string    `json:"role" gorm:"default:user"`
	Active    bool      `json:"active" gorm:"default:true"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ReconSession struct {
	ID          uint        `json:"id" gorm:"primarykey"`
	UserID      uint        `json:"user_id" gorm:"not null"`
	User        User        `json:"user" gorm:"foreignKey:UserID"`
	Name        string      `json:"name" gorm:"not null"`
	Description string      `json:"description"`
	Status      string      `json:"status" gorm:"default:active"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	Files       []ReconFile `json:"files" gorm:"foreignKey:SessionID"`
}

type ReconFile struct {
	ID            uint         `json:"id" gorm:"primarykey"`
	SessionID     uint         `json:"session_id" gorm:"not null"`
	Session       ReconSession `json:"session" gorm:"foreignKey:SessionID"`
	Filename      string       `json:"filename" gorm:"not null"`
	OriginalName  string       `json:"original_name" gorm:"not null"`
	FileType      string       `json:"file_type" gorm:"not null"` // json, html, csv, txt
	Tool          string       `json:"tool"`                      // subdocli, urlcli, etc.
	FileSize      int64        `json:"file_size"`
	FilePath      string       `json:"file_path" gorm:"not null"`
	ProcessedData interface{}  `json:"processed_data" gorm:"type:text"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

func InitDB(cfg *config.Config) (*gorm.DB, error) {
	return Initialize(cfg.DatabaseURL, cfg.QuietMode)
}

func Initialize(databaseURL string, quietMode ...bool) (*gorm.DB, error) {
	// Create data directory if it doesn't exist
	if dir := filepath.Dir(databaseURL); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}

	// Configure logger
	var gormLogger logger.Interface
	if len(quietMode) > 0 && quietMode[0] {
		// Create completely silent logger that discards all output
		gormLogger = logger.New(
			log.New(io.Discard, "", 0),
			logger.Config{
				LogLevel: logger.Silent,
			},
		)
	} else if os.Getenv("ENVIRONMENT") == "development" {
		gormLogger = logger.Default.LogMode(logger.Info)
	} else {
		gormLogger = logger.Default.LogMode(logger.Silent)
	}

	// Open database connection
	db, err := gorm.Open(sqlite.Open(databaseURL), &gorm.Config{
		Logger: gormLogger,
	})
	if err != nil {
		return nil, err
	}

	// Auto-migrate tables
	err = db.AutoMigrate(
		&User{},
		&ReconSession{},
		&ReconFile{},
	)
	if err != nil {
		return nil, err
	}

	// Create default admin user if no users exist
	var userCount int64
	db.Model(&User{}).Count(&userCount)
	if userCount == 0 {
		if err := createDefaultAdmin(db, len(quietMode) > 0 && quietMode[0]); err != nil {
			if len(quietMode) == 0 || !quietMode[0] {
				log.Printf("Warning: Failed to create default admin user: %v", err)
			}
		}
	}

	// Only log success message if not in quiet mode
	if !(len(quietMode) > 0 && quietMode[0]) {
		log.Println("✅ Database initialized successfully")
	}

	return db, nil
}

func createDefaultAdmin(db *gorm.DB, quietMode ...bool) error {
	// Generate proper bcrypt hash for "admin123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	adminUser := User{
		Username: "admin",
		Email:    "admin@reconcli.local",
		Password: string(hashedPassword),
		Role:     "admin",
		Active:   true,
	}

	result := db.Create(&adminUser)
	if result.Error != nil {
		return result.Error
	}

	// Only log if not in quiet mode
	if len(quietMode) == 0 || !quietMode[0] {
		log.Println("🔑 Default admin user created (admin/admin123) - CHANGE PASSWORD!")
	}
	return nil
}
