# VhostCLI Screenshot Functionality

## Overview
VhostCLI now supports automatic screenshot capturing of discovered virtual hosts using two popular tools: **gowitness** and **aquatone**.

## Features Added

### ✅ Screenshot Options
- `--screenshot` - Enable screenshot functionality
- `--screenshot-tool [gowitness|aquatone]` - Choose tool (default: gowitness)
- `--screenshot-timeout INTEGER` - Screenshot timeout in seconds (default: 15)
- `--screenshot-threads INTEGER` - Number of screenshot threads (default: 5)
- `--fullpage` - Take full-page screenshots (gowitness only)

### ✅ Tool Support

#### 🖼️ Gowitness
- Fast screenshot tool written in Go
- Supports full-page screenshots
- Batch processing of URLs
- Installation: `go install github.com/sensepost/gowitness@latest`

#### 🖼️ Aquatone
- Advanced visual inspection tool
- Generates HTML reports with screenshots
- Clustering of similar pages
- Installation: `go install github.com/michenriksen/aquatone@latest`

## Usage Examples

### Basic Screenshot with Gowitness
```bash
reconcli vhostcli --domain example.com --ip 1.2.3.4 --wordlist wordlist.txt --screenshot --screenshot-tool gowitness
```

### Full-page Screenshots with Gowitness

```bash
reconcli vhostcli --domain example.com --ip 1.2.3.4 --wordlist wordlist.txt --screenshot --screenshot-tool gowitness --fullpage
```

### Screenshot with Aquatone

```bash
reconcli vhostcli --domain example.com --ip 1.2.3.4 --wordlist wordlist.txt --screenshot --screenshot-tool aquatone
```

### Advanced Configuration

```bash
reconcli vhostcli --domain example.com --ip 1.2.3.4 --wordlist wordlist.txt \
  --screenshot --screenshot-tool gowitness \
  --screenshot-timeout 30 --screenshot-threads 10 \
  --fullpage --verbose
```

## Output Structure

### With Gowitness
```
vhostcli_output/
├── [target_ip]/
│   ├── screenshots/
│   │   ├── gowitness_batch_[timestamp].txt
│   │   └── [generated screenshots]
│   ├── vhosts_found.json
│   └── vhosts_found.md
```

### With Aquatone
```
vhostcli_output/
├── [target_ip]/
│   ├── aquatone_screenshots/
│   │   ├── report_[timestamp]/
│   │   │   ├── aquatone_report.html
│   │   │   ├── screenshots/
│   │   │   ├── html/
│   │   │   └── headers/
│   │   └── aquatone_urls_[timestamp].txt
│   ├── vhosts_found.json
│   └── vhosts_found.md
```

## Features Integration

✅ **Verbose Output** - Detailed screenshot progress information
✅ **Error Handling** - Graceful handling of missing tools
✅ **Tool Validation** - Automatic checking for tool availability
✅ **Progress Tracking** - Real-time screenshot status updates
✅ **Multiple Engines** - Works with ffuf, httpx, gobuster, vhostfinder
✅ **Resume Support** - Screenshots included in resume functionality

## Installation Requirements

```bash
# Install gowitness
go install github.com/sensepost/gowitness@latest

# Install aquatone
go install github.com/michenriksen/aquatone@latest
```

## Test Results

Successfully tested with:
- ✅ Gowitness basic screenshots
- ✅ Gowitness full-page screenshots
- ✅ Aquatone HTML reports with screenshots
- ✅ Tool availability validation
- ✅ Multiple virtual host discovery and screenshot
- ✅ Integration with all VhostCLI engines

Screenshot functionality seamlessly integrates with existing VhostCLI features including database storage, AI analysis, notifications, and resume capabilities.
