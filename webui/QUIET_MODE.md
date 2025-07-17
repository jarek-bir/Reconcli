# ReconCLI Web UI - Quiet Mode

The ReconCLI Web UI now supports **quiet mode** for cleaner terminal output.

## Usage

### Quiet Mode (Minimal Output)
```bash
# Using environment variable
QUIET=true go run main.go

# Or using the provided script
./start-quiet.sh
```

**Output in quiet mode:**
```
🚀 ReconCLI Web UI ready: http://localhost:8080
📝 Login: admin/admin123
```

### Normal Mode (Verbose Output)
```bash
# Default mode
go run main.go

# Or using the main script
./start.sh
```

**Output in normal mode:**
```
Database logs, Gin framework logs, route registration, etc.
🚀 ReconCLI Web UI starting on port 8080
🌐 Environment: development
📁 Upload directory: uploads
🔗 Access: http://localhost:8080
📝 Default login: admin/admin123
```

## Features

- **Quiet Mode**: Shows only essential startup information (URL and login credentials)
- **Normal Mode**: Shows full debugging information, database logs, and route registration
- **Automatic Detection**: Configured via `QUIET` environment variable
- **Production Ready**: Quiet mode is perfect for production deployments

## Configuration

The quiet mode is controlled by the `QUIET` environment variable in the configuration system:

- `QUIET=true` - Enables quiet mode
- `QUIET=false` or unset - Uses normal verbose mode

## Implementation Details

- Suppresses GORM database logs
- Disables Gin framework debug output
- Hides route registration messages
- Reduces database initialization messages
- Maintains only essential startup and access information
