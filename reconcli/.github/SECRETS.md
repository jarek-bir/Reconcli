# GitHub Actions Secrets Configuration Guide

This document describes the GitHub secrets needed for the CI/CD pipeline.

## Required Secrets

### For PyPI Publishing (Optional)
- `PYPI_API_TOKEN`: API token for publishing to PyPI
  - Go to https://pypi.org/manage/account/token/
  - Create a token with scope for the project
  - Add to GitHub repository secrets

### For Notifications (Optional)
- `DISCORD_WEBHOOK_URL`: Discord webhook URL for build notifications
  - Create a webhook in your Discord server
  - Add the URL to GitHub repository secrets
  
- `SLACK_WEBHOOK_URL`: Slack webhook URL for build notifications (if preferred over Discord)
  - Create a webhook in your Slack workspace
  - Add the URL to GitHub repository secrets

## Setting up Secrets

1. Go to your GitHub repository
2. Navigate to Settings → Secrets and variables → Actions
3. Click "New repository secret"
4. Add the secret name and value
5. Click "Add secret"

## Security Notes

- Never commit secrets to the repository
- Use environment-specific secrets for different stages
- Regularly rotate API tokens and webhook URLs
- Use least-privilege principle for API tokens

## Testing Without Secrets

The CI/CD pipeline is designed to work even without secrets:
- PyPI publishing will be skipped if `PYPI_API_TOKEN` is not present
- Notifications will use a mock endpoint if webhook URLs are not configured
- All other tests and builds will run normally
