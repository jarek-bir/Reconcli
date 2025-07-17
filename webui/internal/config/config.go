package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Environment    string
	DatabaseURL    string
	JWTSecret      string
	JWTExpiration  time.Duration
	UploadDir      string
	MaxUploadSize  int64
	AllowedOrigins []string
	ServerPort     string
	QuietMode      bool
}

func Load() *Config {
	return &Config{
		Environment:    getEnv("ENVIRONMENT", "development"),
		DatabaseURL:    getEnv("DATABASE_URL", "data/reconcli_webui.db"),
		JWTSecret:      getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-in-production"),
		JWTExpiration:  getDurationEnv("JWT_EXPIRATION", "24h"),
		UploadDir:      getEnv("UPLOAD_DIR", "uploads"),
		MaxUploadSize:  getInt64Env("MAX_UPLOAD_SIZE", "50"), // MB
		AllowedOrigins: []string{getEnv("ALLOWED_ORIGINS", "*")},
		ServerPort:     getEnv("PORT", "8080"),
		QuietMode:      getEnv("QUIET", "false") == "true",
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getDurationEnv(key, defaultValue string) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	duration, _ := time.ParseDuration(defaultValue)
	return duration
}

func getInt64Env(key, defaultValue string) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue * 1024 * 1024 // Convert MB to bytes
		}
	}
	defaultInt, _ := strconv.ParseInt(defaultValue, 10, 64)
	return defaultInt * 1024 * 1024
}
