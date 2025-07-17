# ReconCLI Web UI

🌐 **Modern Web Interface for ReconCLI Reconnaissance Toolkit**

## 🚀 Features

- **📁 File Upload**: Support for JSON, HTML, CSV, TXT files from ReconCLI tools
- **🔐 JWT Authentication**: Secure login system with user management
- **📊 Interactive Dashboard**: Real-time statistics and data visualization
- **📂 Session Management**: Organize reconnaissance data by projects/sessions
- **🎨 Modern UI**: Bootstrap 5 responsive interface with dark sidebar
- **📈 Data Analysis**: Built-in file analysis and visualization tools
- **💾 SQLite Database**: Lightweight database for storing metadata and sessions

## 🛠️ Technology Stack

- **Backend**: Go 1.21+ with Gin web framework
- **Database**: SQLite with GORM ORM
- **Authentication**: JWT tokens with bcrypt password hashing
- **Frontend**: Bootstrap 5, Chart.js, Font Awesome
- **File Storage**: Local filesystem with organized directory structure

## 📋 Prerequisites

- Go 1.21 or higher
- Git

## 🚀 Quick Start

### 1. Clone and Setup

```bash
cd webui
cp .env.example .env
```

### 2. Install Dependencies

```bash
go mod tidy
```

### 3. Run the Application

```bash
go run main.go
```

### 4. Access the Web UI

Open your browser and navigate to: `http://localhost:8080`

**Default Login Credentials:**
- Username: `admin`
- Password: `admin123`

> ⚠️ **Security Warning**: Change the default password immediately in production!

## 📁 Project Structure

```
webui/
├── main.go                 # Application entry point
├── go.mod                 # Go module definition
├── .env.example           # Environment configuration template
├── internal/              # Internal application packages
│   ├── api/              # API routes and setup
│   ├── config/           # Configuration management
│   ├── database/         # Database models and setup
│   ├── handlers/         # HTTP request handlers
│   └── middleware/       # HTTP middleware (auth, CORS)
├── web/                  # Web interface files
│   └── templates/        # HTML templates
├── data/                 # Database files (auto-created)
└── uploads/              # Uploaded files storage (auto-created)
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ENVIRONMENT` | Application environment (development/production) | `development` |
| `PORT` | Server port | `8080` |
| `DATABASE_URL` | SQLite database file path | `data/reconcli_webui.db` |
| `JWT_SECRET` | JWT signing secret (change in production!) | `your-super-secret...` |
| `JWT_EXPIRATION` | JWT token expiration time | `24h` |
| `UPLOAD_DIR` | Upload directory path | `uploads` |
| `MAX_UPLOAD_SIZE` | Maximum upload size in MB | `50` |
| `ALLOWED_ORIGINS` | CORS allowed origins | `*` |

### Production Configuration

For production deployment:

1. Set `ENVIRONMENT=production`
2. Change `JWT_SECRET` to a strong, unique secret
3. Configure `ALLOWED_ORIGINS` to specific domains
4. Set up proper SSL/TLS termination
5. Use a reverse proxy (nginx, traefik)

## 📊 API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `GET /api/auth/me` - Get user profile
- `PUT /api/auth/profile` - Update user profile
- `POST /api/auth/change-password` - Change password

### Sessions
- `GET /api/sessions` - List user sessions
- `POST /api/sessions` - Create new session
- `GET /api/sessions/:id` - Get session details
- `PUT /api/sessions/:id` - Update session
- `DELETE /api/sessions/:id` - Delete session

### Files
- `POST /api/upload` - Upload file
- `GET /api/files` - List files
- `GET /api/files/:id` - Get file details
- `GET /api/files/:id/view` - View file content
- `GET /api/files/:id/download` - Download file
- `GET /api/files/:id/analyze` - Analyze file
- `DELETE /api/files/:id` - Delete file

## 📱 Web Pages

- `/` - Landing page with features overview
- `/login` - Authentication page
- `/dashboard` - Main dashboard with statistics and charts
- `/upload` - File upload interface
- `/sessions` - Session management

## 🔒 Security Features

- **JWT Authentication**: Secure token-based authentication
- **Password Hashing**: bcrypt for secure password storage
- **CORS Protection**: Configurable cross-origin resource sharing
- **File Validation**: Type and size validation for uploads
- **SQL Injection Protection**: GORM ORM with parameterized queries
- **XSS Protection**: Proper input sanitization and escaping

## 📈 Dashboard Features

- **Real-time Statistics**: Sessions, files, storage usage
- **Interactive Charts**: File type distribution, tool usage
- **Recent Files Table**: Quick access to latest uploads
- **User Profile**: Account information and settings

## 🗂️ Supported ReconCLI Tools

The web UI supports files from all ReconCLI tools:

- **SubdoCLI** - Subdomain enumeration results
- **URLCLI** - URL discovery outputs
- **PortCLI** - Port scanning data
- **VulnCLI** - Vulnerability scan results
- **DNSCLI** - DNS resolution data
- **HttpCLI** - HTTP analysis results
- **JSCLI** - JavaScript analysis
- **SecretsCLI** - Secret discovery results
- **And more...**

## 🔄 File Processing

The application automatically:
- Validates file types (JSON, HTML, CSV, TXT)
- Stores metadata in the database
- Organizes files by sessions
- Provides file analysis capabilities
- Tracks file usage statistics

## 🐳 Docker Support (Coming Soon)

```dockerfile
# Dockerfile example for future implementation
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o reconcli-webui main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/reconcli-webui .
COPY --from=builder /app/web ./web
CMD ["./reconcli-webui"]
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is part of the ReconCLI toolkit and follows the same license terms.

## 🆘 Troubleshooting

### Common Issues

**Database Connection Error**
```bash
# Ensure data directory exists
mkdir -p data
```

**Permission Issues**
```bash
# Fix upload directory permissions
chmod 755 uploads/
```

**Port Already in Use**
```bash
# Change port in .env file
PORT=8081
```

### Development Tips

1. **Enable Debug Logging**: Set `ENVIRONMENT=development`
2. **Database Reset**: Delete `data/reconcli_webui.db` to reset
3. **File Cleanup**: Clear `uploads/` directory if needed
4. **Hot Reloading**: Use `air` or similar tools for development

## 📞 Support

For issues and questions:
1. Check the main ReconCLI documentation
2. Review the troubleshooting section
3. Open an issue in the main ReconCLI repository

---

**Built with ❤️ for the ReconCLI Community**
