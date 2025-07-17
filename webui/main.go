package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"reconcli-webui/internal/api"
	"reconcli-webui/internal/config"
	"reconcli-webui/internal/database"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Initialize configuration
	cfg := config.Load()

	// Set Gin mode and logging based on quiet mode
	if cfg.QuietMode {
		gin.SetMode(gin.ReleaseMode)
		gin.DefaultWriter = io.Discard // Disable Gin logs
	} else if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize database
	db, err := database.InitDB(cfg)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	// Initialize router
	router := gin.Default()

	// Initialize API routes
	api.SetupRoutes(router, db, cfg)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	if cfg.QuietMode {
		// Only show essential info in quiet mode
		log.Printf("🚀 ReconCLI Web UI ready: http://localhost:%s", port)
		log.Printf("📝 Login: admin/admin123")
	} else {
		// Show detailed info in normal mode
		log.Printf("🚀 ReconCLI Web UI starting on port %s", port)
		log.Printf("🌐 Environment: %s", cfg.Environment)
		log.Printf("📁 Upload directory: %s", cfg.UploadDir)
		log.Printf("🔗 Access: http://localhost:%s", port)
		log.Printf("📝 Default login: admin/admin123")
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	// Create channel to listen for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server:", err)
		}
	}()

	if !cfg.QuietMode {
		log.Printf("✅ Server started successfully")
		log.Printf("🛑 Press Ctrl+C to stop")
	}

	// Wait for interrupt signal
	<-quit

	if !cfg.QuietMode {
		log.Println("🛑 Shutting down server...")
	}

	// Create context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	if !cfg.QuietMode {
		log.Println("✅ Server stopped gracefully")
	}
}
