package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"reconcli-webui/internal/config"
	"reconcli-webui/internal/database"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type UploadHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

type SessionHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

type FileHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewUploadHandler(db *gorm.DB, cfg *config.Config) *UploadHandler {
	return &UploadHandler{db: db, cfg: cfg}
}

func NewSessionHandler(db *gorm.DB, cfg *config.Config) *SessionHandler {
	return &SessionHandler{db: db, cfg: cfg}
}

func NewFileHandler(db *gorm.DB, cfg *config.Config) *FileHandler {
	return &FileHandler{db: db, cfg: cfg}
}

// Upload Handler Methods
func (h *UploadHandler) UploadFile(c *gin.Context) {
	// Create upload directory if it doesn't exist
	if err := os.MkdirAll(h.cfg.UploadDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upload directory"})
		return
	}

	// Parse multipart form
	err := c.Request.ParseMultipartForm(h.cfg.MaxUploadSize)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File too large"})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}
	defer file.Close()

	// Validate file type
	fileType := h.getFileType(header.Filename)
	if !h.isValidFileType(fileType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Supported: json, html, csv, txt"})
		return
	}

	// Generate unique filename
	filename := fmt.Sprintf("%d_%s", time.Now().Unix(), header.Filename)
	filePath := filepath.Join(h.cfg.UploadDir, filename)

	// Save file
	dst, err := os.Create(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// Get session ID from form or create default
	sessionIDStr := c.PostForm("session_id")
	var sessionID uint = 1 // Default session
	if sessionIDStr != "" {
		if id, err := strconv.ParseUint(sessionIDStr, 10, 32); err == nil {
			sessionID = uint(id)
		}
	}

	// Save file record to database
	reconFile := database.ReconFile{
		SessionID:    sessionID,
		Filename:     filename,
		OriginalName: header.Filename,
		FileType:     fileType,
		Tool:         c.PostForm("tool"),
		FileSize:     header.Size,
		FilePath:     filePath,
	}

	if err := h.db.Create(&reconFile).Error; err != nil {
		// Clean up file if database save fails
		os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file record"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "File uploaded successfully",
		"file": gin.H{
			"id":            reconFile.ID,
			"filename":      reconFile.Filename,
			"original_name": reconFile.OriginalName,
			"file_type":     reconFile.FileType,
			"tool":          reconFile.Tool,
			"file_size":     reconFile.FileSize,
			"created_at":    reconFile.CreatedAt,
		},
	})
}

// Session Handler Methods
func (h *SessionHandler) GetSessions(c *gin.Context) {
	userID := c.GetFloat64("user_id")

	var sessions []database.ReconSession
	if err := h.db.Where("user_id = ?", uint(userID)).Preload("Files").Find(&sessions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch sessions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

func (h *SessionHandler) CreateSession(c *gin.Context) {
	userID := c.GetFloat64("user_id")

	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	session := database.ReconSession{
		UserID:      uint(userID),
		Name:        req.Name,
		Description: req.Description,
		Status:      "active",
	}

	if err := h.db.Create(&session).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Session created successfully",
		"session": session,
	})
}

func (h *SessionHandler) GetSession(c *gin.Context) {
	sessionID := c.Param("id")
	userID := c.GetFloat64("user_id")

	var session database.ReconSession
	if err := h.db.Where("id = ? AND user_id = ?", sessionID, uint(userID)).Preload("Files").First(&session).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"session": session})
}

func (h *SessionHandler) UpdateSession(c *gin.Context) {
	sessionID := c.Param("id")
	userID := c.GetFloat64("user_id")

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Status      string `json:"status"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var session database.ReconSession
	if err := h.db.Where("id = ? AND user_id = ?", sessionID, uint(userID)).First(&session).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}

	if req.Name != "" {
		session.Name = req.Name
	}
	if req.Description != "" {
		session.Description = req.Description
	}
	if req.Status != "" {
		session.Status = req.Status
	}

	if err := h.db.Save(&session).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Session updated successfully",
		"session": session,
	})
}

func (h *SessionHandler) DeleteSession(c *gin.Context) {
	sessionID := c.Param("id")
	userID := c.GetFloat64("user_id")

	var session database.ReconSession
	if err := h.db.Where("id = ? AND user_id = ?", sessionID, uint(userID)).First(&session).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}

	// Delete associated files from filesystem
	var files []database.ReconFile
	h.db.Where("session_id = ?", sessionID).Find(&files)
	for _, file := range files {
		os.Remove(file.FilePath)
	}

	// Delete session and files from database
	if err := h.db.Delete(&session).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Session deleted successfully"})
}

// File Handler Methods
func (h *FileHandler) GetFiles(c *gin.Context) {
	sessionID := c.Query("session_id")

	var files []database.ReconFile
	query := h.db.Preload("Session")

	if sessionID != "" {
		query = query.Where("session_id = ?", sessionID)
	}

	if err := query.Find(&files).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch files"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"files": files})
}

func (h *FileHandler) GetFile(c *gin.Context) {
	fileID := c.Param("id")

	var file database.ReconFile
	if err := h.db.Preload("Session").First(&file, fileID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"file": file})
}

func (h *FileHandler) DownloadFile(c *gin.Context) {
	fileID := c.Param("id")

	var file database.ReconFile
	if err := h.db.First(&file, fileID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", file.OriginalName))
	c.File(file.FilePath)
}

func (h *FileHandler) DeleteFile(c *gin.Context) {
	fileID := c.Param("id")

	var file database.ReconFile
	if err := h.db.First(&file, fileID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	// Delete file from filesystem
	os.Remove(file.FilePath)

	// Delete file record from database
	if err := h.db.Delete(&file).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "File deleted successfully"})
}

func (h *FileHandler) ViewFile(c *gin.Context) {
	fileID := c.Param("id")

	var file database.ReconFile
	if err := h.db.First(&file, fileID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	// Read file content
	content, err := os.ReadFile(file.FilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}

	// Return appropriate content based on file type
	switch file.FileType {
	case "json":
		var jsonData interface{}
		if err := json.Unmarshal(content, &jsonData); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid JSON format"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"file":    file,
			"content": jsonData,
			"type":    "json",
		})
	case "html":
		c.JSON(http.StatusOK, gin.H{
			"file":    file,
			"content": string(content),
			"type":    "html",
		})
	default:
		c.JSON(http.StatusOK, gin.H{
			"file":    file,
			"content": string(content),
			"type":    "text",
		})
	}
}

func (h *FileHandler) AnalyzeFile(c *gin.Context) {
	fileID := c.Param("id")

	var file database.ReconFile
	if err := h.db.First(&file, fileID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	// Basic analysis based on file type and content
	content, err := os.ReadFile(file.FilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}

	analysis := gin.H{
		"file_size":   file.FileSize,
		"file_type":   file.FileType,
		"line_count":  strings.Count(string(content), "\n") + 1,
		"char_count":  len(content),
		"tool":        file.Tool,
		"analyzed_at": time.Now(),
	}

	// JSON-specific analysis
	if file.FileType == "json" {
		var jsonData interface{}
		if err := json.Unmarshal(content, &jsonData); err == nil {
			analysis["json_valid"] = true
			// Add more JSON-specific analysis here
		} else {
			analysis["json_valid"] = false
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"file":     file,
		"analysis": analysis,
	})
}

// Helper methods
func (h *UploadHandler) getFileType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".json":
		return "json"
	case ".html", ".htm":
		return "html"
	case ".csv":
		return "csv"
	case ".txt":
		return "txt"
	default:
		return "unknown"
	}
}

func (h *UploadHandler) isValidFileType(fileType string) bool {
	validTypes := []string{"json", "html", "csv", "txt"}
	for _, valid := range validTypes {
		if fileType == valid {
			return true
		}
	}
	return false
}
