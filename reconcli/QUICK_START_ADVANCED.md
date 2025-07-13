# 🎯 Quick Start Guide - Advanced Features

## 🚀 5-Minute Examples

### Example 1: Corporate Admin Discovery
```bash
# Target: admin.company.com discovery
python main.py makewordlist \
  --company "Target Corp" \
  --word-boost admin \
  --pattern subdomain \
  --output-prefix corp_admin

# Output: admin.target.com, corp-admin.target.com, adminpanel.target.com, etc.
```

### Example 2: API Endpoint Brute Force
```bash
# Create API training data
echo -e "/api/users\n/api/auth\n/rest/admin\n/v1/config" > api_patterns.txt

python main.py makewordlist \
  --name api \
  --word-boost api \
  --markovify api_patterns.txt \
  --pattern endpoint \
  --output-prefix api_bruteforce

# Output: /api/admin, /rest/users, /v1/auth, etc.
```

### Example 3: Password Spray Enhancement
```bash
# Combine company info with common passwords
python main.py makewordlist \
  --company "Acme Corp" \
  --birth 2024 \
  --word-boost auth \
  --combine-with /usr/share/wordlists/rockyou.txt \
  --combine-method intersect \
  --min-length 8 \
  --max-words 1000 \
  --output-prefix password_spray

# Output: Company-specific variants of common passwords
```

### Example 4: Resume Large Generation
```bash
# Start large wordlist (might be interrupted)
python main.py makewordlist \
  --advanced \
  --full \
  --markovify /usr/share/wordlists/rockyou.txt \
  --output-prefix massive

# If interrupted, resume from checkpoint
python main.py makewordlist \
  --resume-from massive_resume.json \
  --output-prefix massive_continued
```

## 🔧 Command Cheat Sheet

```bash
# Basic boost
--word-boost admin|auth|panel|qa|api

# Markov AI generation
--markovify training_file.txt --markov-count 1000 --markov-length 2

# Wordlist combination
--combine-with file.txt --combine-method merge|intersect|combine|permute

# Resume interrupted generation
--resume-from checkpoint_file.json

# Export all formats
--export-txt --export-json --export-md

# Quality optimization
--similarity-filter 0.8 --entropy-sort --max-words 5000
```

## 📊 Performance Guidelines

| Target Size | Recommended Options | Expected Output |
|-------------|-------------------|-----------------|
| Small (< 1K) | `--word-boost profile` | 500-1000 words |
| Medium (1-10K) | `--word-boost + --markovify` | 2000-5000 words |
| Large (10K+) | `--advanced --resume-from` | 10000+ words |

**Ready to generate advanced wordlists! 🚀**
