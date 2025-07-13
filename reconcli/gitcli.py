#!/usr/bin/env python3
"""
Git CLI for ReconCLI

Git operations and repository management for ReconCLI toolkit.
Provides version control, backup, and collaboration features.
"""

import os
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

import click


@click.group()
def gitcli():
    """ReconCLI Git Operations

    Git version control and repository management for reconnaissance data.
    """
    pass


def _run_git_command(
    cmd: List[str], cwd: Optional[str] = None, capture_output: bool = True
) -> subprocess.CompletedProcess:
    """Run git command with error handling"""
    try:
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=capture_output, text=True, check=False
        )
        return result
    except Exception as e:
        click.echo(f"❌ Git command failed: {e}")
        return None


def _check_git_repo(path: str = ".") -> bool:
    """Check if directory is a git repository"""
    git_dir = os.path.join(path, ".git")
    return os.path.exists(git_dir)


def _get_repo_status() -> Dict[str, Any]:
    """Get comprehensive repository status"""
    status = {
        "is_repo": _check_git_repo(),
        "branch": None,
        "remote": None,
        "changes": {"staged": [], "unstaged": [], "untracked": []},
        "commits": {"ahead": 0, "behind": 0},
    }

    if not status["is_repo"]:
        return status

    # Get current branch
    result = _run_git_command(["git", "branch", "--show-current"])
    if result and result.returncode == 0:
        status["branch"] = result.stdout.strip()

    # Get remote URL
    result = _run_git_command(["git", "remote", "get-url", "origin"])
    if result and result.returncode == 0:
        status["remote"] = result.stdout.strip()

    # Get status
    result = _run_git_command(["git", "status", "--porcelain"])
    if result and result.returncode == 0:
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            status_code = line[:2]
            filename = line[3:]

            if status_code[0] in ["A", "M", "D", "R", "C"]:
                status["changes"]["staged"].append(filename)
            if status_code[1] in ["M", "D"]:
                status["changes"]["unstaged"].append(filename)
            if status_code == "??":
                status["changes"]["untracked"].append(filename)

    # Get ahead/behind info
    result = _run_git_command(
        ["git", "rev-list", "--count", "--left-right", "HEAD...@{upstream}"]
    )
    if result and result.returncode == 0:
        counts = result.stdout.strip().split("\t")
        if len(counts) == 2:
            status["commits"]["ahead"] = int(counts[0])
            status["commits"]["behind"] = int(counts[1])

    return status


@gitcli.command()
@click.option("--remote", "-r", help="Remote repository URL")
@click.option("--branch", "-b", default="main", help="Initial branch name")
def init(remote: Optional[str], branch: str):
    """Initialize git repository for ReconCLI data"""
    if _check_git_repo():
        click.echo("✅ Repository already initialized")
        return

    try:
        # Initialize repository
        result = _run_git_command(["git", "init", "-b", branch])
        if result.returncode != 0:
            click.echo(f"❌ Failed to initialize repository: {result.stderr}")
            return

        # Create .gitignore for ReconCLI
        gitignore_content = """# ReconCLI specific
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.so
.venv/
venv/
env/

# Sensitive data
*.key
*.pem
api_keys.txt
config.json
.env

# Output directories
output/
results/
exports/
temp/
cache/

# Database files
*.db
*.sqlite
*.sqlite3

# Log files
*.log
logs/

# Resume files
resume.cfg
*.resume

# Backup files
*.backup
*.bak

# OS specific
.DS_Store
Thumbs.db
.directory

# IDE specific
.vscode/
.idea/
*.swp
*.swo
*~

# Large files
*.zip
*.tar.gz
*.tar.bz2
"""

        with open(".gitignore", "w") as f:
            f.write(gitignore_content)

        # Create README if not exists
        if not os.path.exists("README.md"):
            readme_content = f"""# ReconCLI Data Repository

This repository contains reconnaissance data and configurations for ReconCLI.

## Structure
- `configs/` - Configuration files
- `scripts/` - Custom scripts and automation
- `reports/` - Generated reports and findings
- `wordlists/` - Custom wordlists
- `notes/` - Manual notes and documentation

## Usage
```bash
# Update repository
git pull

# Add new findings
git add reports/
git commit -m "Add new reconnaissance findings"
git push

# Create backup
python -m reconcli.gitcli backup --tag daily-backup
```

## Security
- Never commit sensitive data (API keys, credentials)
- Use .gitignore to exclude sensitive files
- Regular backups with git tags

Created: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
            with open("README.md", "w") as f:
                f.write(readme_content)

        # Initial commit
        _run_git_command(["git", "add", ".gitignore", "README.md"])
        _run_git_command(["git", "commit", "-m", "Initial ReconCLI repository setup"])

        # Add remote if provided
        if remote:
            result = _run_git_command(["git", "remote", "add", "origin", remote])
            if result.returncode == 0:
                click.echo(f"✅ Added remote: {remote}")
            else:
                click.echo(f"⚠️ Could not add remote: {result.stderr}")

        click.echo("✅ ReconCLI repository initialized successfully!")
        click.echo(f"📁 Branch: {branch}")
        if remote:
            click.echo(f"🌐 Remote: {remote}")

    except Exception as e:
        click.echo(f"❌ Error initializing repository: {e}")


@gitcli.command()
def status():
    """Show comprehensive repository status"""
    status = _get_repo_status()

    if not status["is_repo"]:
        click.echo("❌ Not a git repository")
        click.echo("Run 'python -m reconcli.gitcli init' to initialize")
        return

    click.echo("📊 ReconCLI Repository Status")
    click.echo("=" * 40)

    # Basic info
    click.echo(f"🌿 Branch: {status['branch'] or 'unknown'}")
    if status["remote"]:
        click.echo(f"🌐 Remote: {status['remote']}")

    # Changes
    total_changes = (
        len(status["changes"]["staged"])
        + len(status["changes"]["unstaged"])
        + len(status["changes"]["untracked"])
    )

    if total_changes == 0:
        click.echo("✅ Working directory clean")
    else:
        click.echo(f"📝 Changes: {total_changes} files")

        if status["changes"]["staged"]:
            click.echo(f"  🟢 Staged: {len(status['changes']['staged'])}")
            for file in status["changes"]["staged"][:5]:
                click.echo(f"    {file}")
            if len(status["changes"]["staged"]) > 5:
                click.echo(f"    ... and {len(status['changes']['staged']) - 5} more")

        if status["changes"]["unstaged"]:
            click.echo(f"  🟡 Modified: {len(status['changes']['unstaged'])}")
            for file in status["changes"]["unstaged"][:5]:
                click.echo(f"    {file}")
            if len(status["changes"]["unstaged"]) > 5:
                click.echo(f"    ... and {len(status['changes']['unstaged']) - 5} more")

        if status["changes"]["untracked"]:
            click.echo(f"  🔴 Untracked: {len(status['changes']['untracked'])}")
            for file in status["changes"]["untracked"][:5]:
                click.echo(f"    {file}")
            if len(status["changes"]["untracked"]) > 5:
                click.echo(
                    f"    ... and {len(status['changes']['untracked']) - 5} more"
                )

    # Sync status
    if status["commits"]["ahead"] > 0 or status["commits"]["behind"] > 0:
        click.echo("🔄 Sync Status:")
        if status["commits"]["ahead"] > 0:
            click.echo(f"  ⬆️  {status['commits']['ahead']} commits ahead")
        if status["commits"]["behind"] > 0:
            click.echo(f"  ⬇️  {status['commits']['behind']} commits behind")
    else:
        click.echo("✅ Up to date with remote")


@gitcli.command()
@click.argument("message")
@click.option("--add-all", "-a", is_flag=True, help="Add all changes before commit")
@click.option("--push", "-p", is_flag=True, help="Push after commit")
def commit(message: str, add_all: bool, push: bool):
    """Commit changes with message"""
    if not _check_git_repo():
        click.echo("❌ Not a git repository")
        return

    try:
        # Add all changes if requested
        if add_all:
            result = _run_git_command(["git", "add", "."])
            if result.returncode != 0:
                click.echo(f"❌ Failed to add changes: {result.stderr}")
                return
            click.echo("✅ Added all changes")

        # Check if there are staged changes
        result = _run_git_command(["git", "diff", "--staged", "--quiet"])
        if result.returncode == 0:
            click.echo("⚠️ No staged changes to commit")
            return

        # Commit
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_message = f"{message}\n\nCommitted: {timestamp}"

        result = _run_git_command(["git", "commit", "-m", full_message])
        if result.returncode != 0:
            click.echo(f"❌ Commit failed: {result.stderr}")
            return

        click.echo(f"✅ Committed: {message}")

        # Push if requested
        if push:
            result = _run_git_command(["git", "push"])
            if result.returncode == 0:
                click.echo("✅ Pushed to remote")
            else:
                click.echo(f"⚠️ Push failed: {result.stderr}")

    except Exception as e:
        click.echo(f"❌ Error during commit: {e}")


@gitcli.command()
@click.option("--tag", "-t", help="Create tagged backup")
@click.option("--message", "-m", help="Backup message")
@click.option("--include-output", is_flag=True, help="Include output directory")
def backup(tag: Optional[str], message: Optional[str], include_output: bool):
    """Create repository backup with optional tagging"""
    if not _check_git_repo():
        click.echo("❌ Not a git repository")
        return

    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Add changes (excluding output by default)
        if include_output:
            result = _run_git_command(["git", "add", "."])
        else:
            # Add everything except output directories
            result = _run_git_command(
                [
                    "git",
                    "add",
                    ".",
                    ":(exclude)output/*",
                    ":(exclude)results/*",
                    ":(exclude)exports/*",
                ]
            )

        if result.returncode != 0:
            click.echo(f"❌ Failed to add changes: {result.stderr}")
            return

        # Check if there are changes to commit
        result = _run_git_command(["git", "diff", "--staged", "--quiet"])
        if result.returncode != 0:  # There are staged changes
            # Commit backup
            backup_message = message or f"Backup {timestamp}"
            result = _run_git_command(
                ["git", "commit", "-m", f"[BACKUP] {backup_message}"]
            )
            if result.returncode != 0:
                click.echo(f"❌ Backup commit failed: {result.stderr}")
                return
            click.echo(f"✅ Backup committed: {backup_message}")
        else:
            click.echo("ℹ️ No changes to backup")

        # Create tag if requested
        if tag:
            tag_name = f"{tag}_{timestamp}" if not tag.endswith(timestamp) else tag
            tag_message = (
                f"Backup created on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            if message:
                tag_message += f"\n{message}"

            result = _run_git_command(["git", "tag", "-a", tag_name, "-m", tag_message])
            if result.returncode == 0:
                click.echo(f"✅ Created tag: {tag_name}")
            else:
                click.echo(f"⚠️ Failed to create tag: {result.stderr}")

        # Push if remote exists
        result = _run_git_command(["git", "remote"])
        if result.returncode == 0 and result.stdout.strip():
            result = _run_git_command(["git", "push"])
            if result.returncode == 0:
                click.echo("✅ Pushed backup to remote")

                # Push tags if created
                if tag:
                    _run_git_command(["git", "push", "--tags"])
                    click.echo("✅ Pushed tags to remote")
            else:
                click.echo(f"⚠️ Failed to push: {result.stderr}")

    except Exception as e:
        click.echo(f"❌ Error creating backup: {e}")


@gitcli.command()
@click.option("--all", "-a", is_flag=True, help="Show all tags")
@click.option("--pattern", "-p", help="Filter tags by pattern")
def tags(all: bool, pattern: Optional[str]):
    """List repository tags"""
    if not _check_git_repo():
        click.echo("❌ Not a git repository")
        return

    try:
        cmd = ["git", "tag", "-l"]
        if pattern:
            cmd.append(pattern)
        elif not all:
            cmd.extend(["-n", "10"])  # Limit to recent tags

        result = _run_git_command(cmd)
        if result.returncode != 0:
            click.echo(f"❌ Failed to list tags: {result.stderr}")
            return

        tags_list = result.stdout.strip().split("\n") if result.stdout.strip() else []

        if not tags_list:
            click.echo("ℹ️ No tags found")
            return

        click.echo(f"🏷️  Repository Tags ({len(tags_list)})")
        click.echo("=" * 40)

        for tag in tags_list:
            if tag:
                # Get tag info
                result = _run_git_command(
                    ["git", "show", "--format=%ci %s", "--no-patch", tag]
                )
                if result.returncode == 0 and result.stdout.strip():
                    info = result.stdout.strip()
                    click.echo(f"📌 {tag}")
                    click.echo(f"   {info}")
                else:
                    click.echo(f"📌 {tag}")

    except Exception as e:
        click.echo(f"❌ Error listing tags: {e}")


@gitcli.command()
@click.argument("tag_name")
@click.option(
    "--force", "-f", is_flag=True, help="Force checkout (discard local changes)"
)
def restore(tag_name: str, force: bool):
    """Restore repository to specific tag or commit"""
    if not _check_git_repo():
        click.echo("❌ Not a git repository")
        return

    try:
        # Check if tag exists
        result = _run_git_command(["git", "rev-parse", "--verify", tag_name])
        if result.returncode != 0:
            click.echo(f"❌ Tag/commit '{tag_name}' not found")
            return

        # Check for uncommitted changes
        if not force:
            result = _run_git_command(["git", "diff", "--quiet"])
            if result.returncode != 0:
                click.echo("⚠️ You have uncommitted changes")
                click.echo("Use --force to discard changes or commit them first")
                return

        # Checkout tag
        cmd = ["git", "checkout", tag_name]
        if force:
            cmd.append("--force")

        result = _run_git_command(cmd, capture_output=False)
        if result.returncode == 0:
            click.echo(f"✅ Restored to {tag_name}")
        else:
            click.echo("❌ Failed to restore: checkout failed")

    except Exception as e:
        click.echo(f"❌ Error during restore: {e}")


@gitcli.command()
@click.option("--limit", "-l", default=10, help="Number of commits to show")
@click.option("--oneline", is_flag=True, help="Show compact format")
def log(limit: int, oneline: bool):
    """Show commit history"""
    if not _check_git_repo():
        click.echo("❌ Not a git repository")
        return

    try:
        cmd = ["git", "log", f"-{limit}"]
        if oneline:
            cmd.append("--oneline")
        else:
            cmd.extend(["--format=%h %ci %s (%an)"])

        result = _run_git_command(cmd, capture_output=False)
        if result.returncode != 0:
            click.echo("❌ Failed to show log")

    except Exception as e:
        click.echo(f"❌ Error showing log: {e}")


@gitcli.command()
def sync():
    """Sync with remote repository (pull + push)"""
    if not _check_git_repo():
        click.echo("❌ Not a git repository")
        return

    try:
        # Check for remote
        result = _run_git_command(["git", "remote"])
        if result.returncode != 0 or not result.stdout.strip():
            click.echo("⚠️ No remote repository configured")
            return

        # Pull changes
        click.echo("🔄 Pulling changes from remote...")
        result = _run_git_command(["git", "pull"])
        if result.returncode == 0:
            click.echo("✅ Pulled changes successfully")
        else:
            click.echo(f"⚠️ Pull failed: {result.stderr}")
            return

        # Check for local changes to push
        result = _run_git_command(
            ["git", "rev-list", "--count", "HEAD", "--not", "--remotes"]
        )
        if result.returncode == 0:
            ahead_count = int(result.stdout.strip()) if result.stdout.strip() else 0
            if ahead_count > 0:
                click.echo(f"⬆️  Pushing {ahead_count} local commits...")
                result = _run_git_command(["git", "push"])
                if result.returncode == 0:
                    click.echo("✅ Pushed changes successfully")
                else:
                    click.echo(f"⚠️ Push failed: {result.stderr}")
            else:
                click.echo("✅ Repository is up to date")

    except Exception as e:
        click.echo(f"❌ Error during sync: {e}")


@gitcli.command()
@click.argument("files", nargs=-1)
@click.option("--all", "-a", is_flag=True, help="Add all files")
@click.option("--exclude-output", is_flag=True, help="Exclude output directories")
def add(files: tuple, all: bool, exclude_output: bool):
    """Add files to staging area"""
    if not _check_git_repo():
        click.echo("❌ Not a git repository")
        return

    try:
        if all:
            if exclude_output:
                cmd = [
                    "git",
                    "add",
                    ".",
                    ":(exclude)output/*",
                    ":(exclude)results/*",
                    ":(exclude)exports/*",
                ]
            else:
                cmd = ["git", "add", "."]
        elif files:
            cmd = ["git", "add"] + list(files)
        else:
            click.echo("⚠️ Specify files to add or use --all")
            return

        result = _run_git_command(cmd)
        if result.returncode == 0:
            if all:
                click.echo("✅ Added all files to staging")
            else:
                click.echo(f"✅ Added {len(files)} files to staging")
        else:
            click.echo(f"❌ Failed to add files: {result.stderr}")

    except Exception as e:
        click.echo(f"❌ Error adding files: {e}")


if __name__ == "__main__":
    gitcli()
