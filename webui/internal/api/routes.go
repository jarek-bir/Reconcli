package api

import (
	"reconcli-webui/internal/config"
	"reconcli-webui/internal/handlers"
	"reconcli-webui/internal/middleware"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRoutes(router *gin.Engine, db *gorm.DB, cfg *config.Config) {
	// Initialize handlers
	authHandler := handlers.NewAuthHandler(db, cfg)
	uploadHandler := handlers.NewUploadHandler(db, cfg)
	sessionHandler := handlers.NewSessionHandler(db, cfg)
	fileHandler := handlers.NewFileHandler(db, cfg)

	// Middleware
	router.Use(middleware.CORS(cfg.AllowedOrigins))
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Serve static files
	router.Static("/static", "./web/static")
	router.LoadHTMLGlob("web/templates/*.html")

	// Public routes
	public := router.Group("/")
	{
		// Web UI routes
		public.GET("/", func(c *gin.Context) {
			c.HTML(200, "index.html", gin.H{
				"title": "ReconCLI Web UI",
			})
		})
		public.GET("/login", func(c *gin.Context) {
			c.HTML(200, "login.html", gin.H{
				"title": "Login - ReconCLI",
			})
		})

		// Auth API routes
		public.POST("/api/auth/login", authHandler.Login)
		public.POST("/api/auth/register", authHandler.Register)
	}

	// Protected routes
	protected := router.Group("/api")
	protected.Use(middleware.AuthRequired(cfg.JWTSecret))
	{
		// Auth routes
		protected.GET("/auth/me", authHandler.GetProfile)
		protected.PUT("/auth/profile", authHandler.UpdateProfile)
		protected.POST("/auth/change-password", authHandler.ChangePassword)

		// Session management
		protected.GET("/sessions", sessionHandler.GetSessions)
		protected.POST("/sessions", sessionHandler.CreateSession)
		protected.GET("/sessions/:id", sessionHandler.GetSession)
		protected.PUT("/sessions/:id", sessionHandler.UpdateSession)
		protected.DELETE("/sessions/:id", sessionHandler.DeleteSession)

		// File upload and management
		protected.POST("/upload", uploadHandler.UploadFile)
		protected.GET("/files", fileHandler.GetFiles)
		protected.GET("/files/:id", fileHandler.GetFile)
		protected.GET("/files/:id/download", fileHandler.DownloadFile)
		protected.DELETE("/files/:id", fileHandler.DeleteFile)

		// File processing and viewing
		protected.GET("/files/:id/view", fileHandler.ViewFile)
		protected.GET("/files/:id/analyze", fileHandler.AnalyzeFile)
	}

	// Protected web routes
	protectedWeb := router.Group("/")
	protectedWeb.Use(middleware.WebAuthRequired(cfg.JWTSecret))
	{
		protectedWeb.GET("/dashboard", func(c *gin.Context) {
			c.HTML(200, "dashboard.html", gin.H{
				"title": "Dashboard - ReconCLI",
			})
		})
		protectedWeb.GET("/sessions", func(c *gin.Context) {
			c.HTML(200, "sessions.html", gin.H{
				"title": "Sessions - ReconCLI",
			})
		})
		protectedWeb.GET("/upload", func(c *gin.Context) {
			c.HTML(200, "upload.html", gin.H{
				"title": "Upload Files - ReconCLI",
			})
		})
		protectedWeb.GET("/profile", func(c *gin.Context) {
			c.HTML(200, "profile.html", gin.H{
				"title": "Profile - ReconCLI",
			})
		})
		protectedWeb.GET("/tools", func(c *gin.Context) {
			c.HTML(200, "tools.html", gin.H{
				"title": "Tools - ReconCLI",
			})
		})
		protectedWeb.GET("/files", func(c *gin.Context) {
			c.HTML(200, "files.html", gin.H{
				"title": "Files - ReconCLI",
			})
		})
		protectedWeb.GET("/viewer", func(c *gin.Context) {
			c.HTML(200, "viewer.html", gin.H{
				"title": "File Viewer - ReconCLI",
			})
		})
	}
}
