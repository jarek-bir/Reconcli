# Local Security Testing for ReconCLI

This directory contains local security testing tools that are **NOT** pushed to the public repository.

## 🔒 Available Security Tools

### 1. Bandit Security Scanner
```bash
# Quick scan
bandit -r . -ll --exclude=__pycache__,tests

# Full scan with report
./security_test.sh
```

### 2. Auto-fix Common Issues
```bash
# Apply automatic fixes (review before commit!)
./security_autofix.sh
```

### 3. Manual Security Review
- Check `SECURITY_IMPROVEMENTS.md` for detailed findings
- Review `security_reports/` for detailed reports

## 📋 Security Workflow

1. **Before committing code:**
   ```bash
   ./security_test.sh
   ```

2. **Fix high-priority issues:**
   - SSL verification disabled (B501)
   - Shell injection (B605)
   - Weak MD5 hashes (B324)

3. **Auto-fix where possible:**
   ```bash
   ./security_autofix.sh
   # Review changes before committing!
   ```

## 🚨 Important Notes

- These tools are for **local development only**
- They contain internal security configurations
- Never push security reports to public repositories
- Always review auto-fixes before committing

## 📊 Current Security Status

Run `./security_test.sh` to see:
- Total issues found: 31
- High severity: 24 (mostly SSL verification)
- Medium severity: 7 (temp directories, etc.)

## 🔧 Quick Fixes

Most issues can be fixed by:
1. Changing `verify=False` to `verify=True` in requests
2. Using `subprocess.run()` instead of `os.system()`
3. Adding `usedforsecurity=False` to MD5 hashes
4. Using `tempfile.gettempdir()` instead of hardcoded `/tmp`
