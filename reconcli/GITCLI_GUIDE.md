# GITCLI - Git Operations for ReconCLI

## 🔧 Overview

GitCLI is a comprehensive git operations and repository management module for ReconCLI. It provides version control capabilities specifically designed for reconnaissance data, with features like automated backups, tagging, and security-focused file management.

## 🚀 Features

- **Repository Management**: Initialize and manage reconnaissance data repositories
- **Automated Backups**: Create tagged backups with timestamp and metadata
- **Security-Focused .gitignore**: Prevents accidental commit of sensitive data
- **Comprehensive Status**: Detailed repository status with changes tracking
- **Tag Management**: Create and manage backup/milestone tags
- **Sync Operations**: Pull and push operations with conflict detection
- **Resume-Safe Operations**: Exclude temporary files and output directories
- **Professional Workflows**: Designed for reconnaissance team collaboration

## 🔧 Installation & Setup

### Prerequisites
```bash
# Git must be installed
git --version

# Optional: Configure global git settings
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### Integration Methods

#### Method 1: Through main ReconCLI
```bash
python main.py gitcli [command]
```

#### Method 2: Alternative entry point
```bash
python reconcli_csvtk.py gitcli [command]
```

#### Method 3: Direct module execution
```bash
python gitcli.py [command]
python -m gitcli [command]
```

## 📋 Commands

### 🚀 init
Initialize a new git repository for ReconCLI data
```bash
python reconcli_csvtk.py gitcli init [options]

# Examples:
python reconcli_csvtk.py gitcli init
python reconcli_csvtk.py gitcli init --remote https://github.com/user/recon-data.git
python reconcli_csvtk.py gitcli init --branch develop --remote origin_url
```

**Options:**
- `--remote URL`: Remote repository URL for synchronization
- `--branch NAME`: Initial branch name (default: main)

**Generated Files:**
- `.gitignore` - Security-focused ignore patterns
- `README.md` - Repository documentation template
- Initial commit with setup files

### 📊 status
Show comprehensive repository status
```bash
python reconcli_csvtk.py gitcli status

# Output example:
📊 ReconCLI Repository Status
========================================
🌿 Branch: main
🌐 Remote: https://github.com/user/recon-data.git
📝 Changes: 5 files
  🟢 Staged: 2
    reports/tesla_analysis.md
    configs/custom_rules.json
  🟡 Modified: 2
    output/subdomains.csv
    notes/findings.txt
  🔴 Untracked: 1
    scripts/custom_enum.py
✅ Up to date with remote
```

### 💾 commit
Commit changes with automatic timestamping
```bash
python reconcli_csvtk.py gitcli commit "message" [options]

# Examples:
python reconcli_csvtk.py gitcli commit "Add Tesla subdomain analysis"
python reconcli_csvtk.py gitcli commit "Update vulnerability findings" --add-all
python reconcli_csvtk.py gitcli commit "Daily recon update" --add-all --push
```

**Options:**
- `--add-all, -a`: Add all changes before commit
- `--push, -p`: Push to remote after successful commit

### 🏷️ backup
Create repository backup with optional tagging
```bash
python reconcli_csvtk.py gitcli backup [options]

# Examples:
python reconcli_csvtk.py gitcli backup --tag daily-backup
python reconcli_csvtk.py gitcli backup --tag milestone-v1.0 --message "First major milestone"
python reconcli_csvtk.py gitcli backup --include-output --tag full-backup
```

**Options:**
- `--tag NAME`: Create tagged backup
- `--message TEXT`: Backup message/description
- `--include-output`: Include output directories (normally excluded)

### 🏷️ tags
List and manage repository tags
```bash
python reconcli_csvtk.py gitcli tags [options]

# Examples:
python reconcli_csvtk.py gitcli tags
python reconcli_csvtk.py gitcli tags --all
python reconcli_csvtk.py gitcli tags --pattern "daily-*"
```

**Options:**
- `--all, -a`: Show all tags
- `--pattern PATTERN`: Filter tags by pattern

### ⏪ restore
Restore repository to specific tag or commit
```bash
python reconcli_csvtk.py gitcli restore <tag_name> [options]

# Examples:
python reconcli_csvtk.py gitcli restore daily-backup_20250712_143022
python reconcli_csvtk.py gitcli restore milestone-v1.0
python reconcli_csvtk.py gitcli restore HEAD~1 --force
```

**Options:**
- `--force, -f`: Force restore (discard local changes)

### 📜 log
Show commit history
```bash
python reconcli_csvtk.py gitcli log [options]

# Examples:
python reconcli_csvtk.py gitcli log
python reconcli_csvtk.py gitcli log --limit 20
python reconcli_csvtk.py gitcli log --oneline
```

**Options:**
- `--limit NUM`: Number of commits to show (default: 10)
- `--oneline`: Compact one-line format

### 🔄 sync
Synchronize with remote repository
```bash
python reconcli_csvtk.py gitcli sync

# Performs:
# 1. git pull (fetch remote changes)
# 2. git push (upload local commits)
# 3. Status report
```

### ➕ add
Add files to staging area
```bash
python reconcli_csvtk.py gitcli add [files...] [options]

# Examples:
python reconcli_csvtk.py gitcli add reports/tesla.md configs/rules.json
python reconcli_csvtk.py gitcli add --all
python reconcli_csvtk.py gitcli add --all --exclude-output
```

**Options:**
- `--all, -a`: Add all files
- `--exclude-output`: Exclude output directories

## 🎯 Usage Examples

### Basic Reconnaissance Workflow
```bash
# Initialize repository for new target
python reconcli_csvtk.py gitcli init --remote https://github.com/team/tesla-recon.git

# Daily work cycle
python reconcli_csvtk.py gitcli add reports/ configs/
python reconcli_csvtk.py gitcli commit "Daily Tesla reconnaissance findings"
python reconcli_csvtk.py gitcli sync

# Create milestone backup
python reconcli_csvtk.py gitcli backup --tag milestone-week1 --message "Week 1 complete"
```

### Team Collaboration
```bash
# Start of day - sync with team
python reconcli_csvtk.py gitcli sync

# Check what changed
python reconcli_csvtk.py gitcli status
python reconcli_csvtk.py gitcli log --limit 5

# Add your findings
python reconcli_csvtk.py gitcli add --all --exclude-output
python reconcli_csvtk.py gitcli commit "Add API endpoint analysis" --push
```

### Backup and Recovery
```bash
# Create comprehensive backup
python reconcli_csvtk.py gitcli backup --tag critical-backup --include-output

# List available backups
python reconcli_csvtk.py gitcli tags --pattern "*backup*"

# Restore from backup if needed
python reconcli_csvtk.py gitcli restore critical-backup_20250712_143022
```

### Large Project Management
```bash
# Weekly automated backup
python reconcli_csvtk.py gitcli backup --tag weekly-$(date +%Y%m%d)

# Monthly milestone
python reconcli_csvtk.py gitcli backup --tag monthly-milestone --message "Monthly progress review"

# Emergency restore
python reconcli_csvtk.py gitcli restore milestone-v1.0 --force
```

## 🛡️ Security Features

### Automatic .gitignore
GitCLI creates a comprehensive .gitignore file that prevents accidental commits of:

#### 🚨 Sensitive Data
- API keys and tokens (`*.key`, `*.pem`, `api_keys.txt`)
- Configuration files (`config.json`, `.env`)
- Credential files

#### 📁 Temporary/Output Files
- Output directories (`output/`, `results/`, `exports/`)
- Cache directories (`cache/`, `temp/`)
- Resume files (`resume.cfg`, `*.resume`)

#### 🗄️ Database Files
- SQLite databases (`*.db`, `*.sqlite`, `*.sqlite3`)
- Database dumps and backups

#### 📝 Log Files
- Application logs (`*.log`, `logs/`)
- Debug files

### Security Categories

#### 🚨 NEVER COMMIT
- API keys and credentials
- Database files with sensitive data
- Personal configuration files
- Large binary files

#### 🟠 REVIEW BEFORE COMMIT
- Configuration templates
- Sample data
- Documentation with examples

#### ✅ SAFE TO COMMIT
- Analysis reports
- Wordlists
- Scripts and tools
- Documentation

## 📊 Repository Structure

### Recommended Layout
```
recon-project/
├── .git/                    # Git repository data
├── .gitignore              # Security-focused ignore rules
├── README.md               # Project documentation
├── configs/                # Configuration files
│   ├── dns_resolvers.txt
│   ├── wordlists.json
│   └── custom_rules.yaml
├── reports/                # Analysis reports
│   ├── tesla_analysis.md
│   ├── vulnerability_summary.json
│   └── weekly_report.pdf
├── scripts/                # Custom scripts
│   ├── custom_enum.py
│   ├── automation.sh
│   └── helpers.py
├── wordlists/             # Custom wordlists
│   ├── company_specific.txt
│   ├── technology_terms.txt
│   └── mutations.txt
├── notes/                 # Manual notes
│   ├── findings.md
│   ├── methodologies.txt
│   └── lessons_learned.md
└── output/                # Excluded from git
    ├── subdomains.csv
    ├── urls.txt
    └── temp_files/
```

### File Categories

#### ✅ Version Controlled
- Configuration files
- Reports and documentation
- Custom scripts and tools
- Wordlists and patterns
- Manual notes and findings

#### ❌ Excluded from Version Control
- Temporary output files
- Database files
- Sensitive credentials
- Large binary files
- Cache directories

## 🔄 Integration Workflows

### Database Integration
```bash
# Export database findings and commit
python reconcli_csvtk.py dbcli export --table subdomains --format csv
python reconcli_csvtk.py gitcli add reports/
python reconcli_csvtk.py gitcli commit "Update subdomain database export"

# Backup database schema (not data)
python reconcli_csvtk.py gitcli add configs/database_schema.sql
python reconcli_csvtk.py gitcli commit "Update database schema"
```

### CSVTK Analysis Integration
```bash
# Generate analysis reports
python reconcli_csvtk.py csvtkcli security-report data.csv
python reconcli_csvtk.py gitcli add admin_domains.csv api_endpoints.csv security_summary.md
python reconcli_csvtk.py gitcli commit "Add security analysis results"
```

### Automated Workflows
```bash
#!/bin/bash
# Daily automation script

# Sync with team
python reconcli_csvtk.py gitcli sync

# Export fresh data
python reconcli_csvtk.py dbcli export --table subdomains --analysis

# Generate reports
python reconcli_csvtk.py csvtkcli security-report output/exports/subdomains_export.csv

# Commit findings
python reconcli_csvtk.py gitcli add reports/ --exclude-output
python reconcli_csvtk.py gitcli commit "Daily automated update $(date)"

# Create weekly backup (on Fridays)
if [ $(date +%u) -eq 5 ]; then
    python reconcli_csvtk.py gitcli backup --tag weekly-backup-$(date +%Y%m%d)
fi

# Sync final results
python reconcli_csvtk.py gitcli sync
```

## ⚡ Performance Tips

1. **Large Repositories**: Use `--exclude-output` for routine commits
2. **Binary Files**: Store large files externally (Git LFS recommended)
3. **Frequent Commits**: Make small, focused commits with clear messages
4. **Tag Strategy**: Use consistent tagging for milestones and backups
5. **Remote Sync**: Regular sync prevents merge conflicts

## 🚨 Best Practices

### Commit Message Guidelines
```bash
# Good commit messages
python reconcli_csvtk.py gitcli commit "Add Tesla subdomain enumeration results"
python reconcli_csvtk.py gitcli commit "Update vulnerability scanning methodology"
python reconcli_csvtk.py gitcli commit "Fix DNS resolver configuration"

# Avoid generic messages
python reconcli_csvtk.py gitcli commit "update"
python reconcli_csvtk.py gitcli commit "fixes"
python reconcli_csvtk.py gitcli commit "changes"
```

### Backup Strategy
```bash
# Daily backups
python reconcli_csvtk.py gitcli backup --tag daily-$(date +%Y%m%d)

# Weekly milestones
python reconcli_csvtk.py gitcli backup --tag weekly-milestone --message "Week $(date +%V) progress"

# Project milestones
python reconcli_csvtk.py gitcli backup --tag project-complete --message "Tesla reconnaissance complete"
```

### Team Collaboration
1. **Sync First**: Always sync before starting work
2. **Clear Messages**: Use descriptive commit messages
3. **Regular Commits**: Commit frequently with logical groupings
4. **Conflict Resolution**: Communicate with team on conflicts
5. **Documentation**: Keep README.md updated

## 🔧 Configuration

### Git Configuration
```bash
# Set global configuration
git config --global user.name "Recon Team Member"
git config --global user.email "recon@company.com"

# Set project-specific config
git config user.name "Project Specific Name"
git config user.email "project@company.com"
```

### Remote Repositories
```bash
# GitHub
python reconcli_csvtk.py gitcli init --remote https://github.com/team/recon-project.git

# GitLab
python reconcli_csvtk.py gitcli init --remote https://gitlab.com/team/recon-project.git

# Private server
python reconcli_csvtk.py gitcli init --remote git@server.com:team/recon-project.git
```

## 🚨 Troubleshooting

### Common Issues

**Repository not initialized**
```bash
python reconcli_csvtk.py gitcli init
```

**Merge conflicts**
```bash
# Check status
python reconcli_csvtk.py gitcli status

# Manual resolution required
git status
git mergetool
python reconcli_csvtk.py gitcli commit "Resolve merge conflicts"
```

**Large file issues**
```bash
# Remove large files from history
git filter-branch --tree-filter 'rm -f large_file.dat' HEAD

# Use .gitignore for future prevention
echo "*.dat" >> .gitignore
```

**Authentication issues**
```bash
# Configure SSH keys for remote repositories
ssh-keygen -t ed25519 -C "your_email@example.com"

# Or use token authentication
git config credential.helper store
```

## 📈 Advanced Features

### Custom Hooks
Create `.git/hooks/pre-commit` for automated checks:
```bash
#!/bin/bash
# Pre-commit hook to prevent sensitive data

# Check for API keys
if grep -r "api_key\|password\|secret" --include="*.py" --include="*.json" .; then
    echo "⚠️ Potential sensitive data detected!"
    exit 1
fi

# Check file sizes
find . -size +10M -not -path "./.git/*" -exec echo "⚠️ Large file: {}" \;
```

### Branch Strategies
```bash
# Feature branches for major changes
git checkout -b feature/new-target-analysis
python reconcli_csvtk.py gitcli commit "Work on new feature"
git checkout main
git merge feature/new-target-analysis

# Hotfix branches for urgent fixes
git checkout -b hotfix/critical-bug
python reconcli_csvtk.py gitcli commit "Fix critical vulnerability detection bug"
```

---

**Author**: ReconCLI Team
**Version**: 1.0
**Last Updated**: July 2025
