# Contributing to ReconCLI

We welcome contributions to ReconCLI! This document provides guidelines for contributing to the project.

## 🚀 Quick Start

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Reconcli.git
   cd Reconcli
   ```

3. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

4. Install development dependencies:
   ```bash
   pip install -e .
   pip install -r requirements-dev.txt
   ```

## 🔧 Development Workflow

### Setting up Development Environment

```bash
# Install pre-commit hooks (optional but recommended)
pip install pre-commit
pre-commit install

# Run tests to ensure everything works
pytest

# Run code quality checks
black --check .
isort --check-only .
flake8 .
bandit -r .
```

### Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our coding standards
3. Add tests for new functionality
4. Run the test suite:
   ```bash
   pytest tests/
   ```

5. Run code quality checks:
   ```bash
   black .
   isort .
   flake8 .
   ```

6. Commit your changes:
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

7. Push to your fork and submit a pull request

## 📝 Coding Standards

### Python Style Guide

- Follow PEP 8 (enforced by flake8)
- Use Black for code formatting (line length: 88 characters)
- Use isort for import sorting
- Add type hints where appropriate
- Write docstrings for all public functions and classes

### Code Examples

```python
def process_urls(urls: List[str], output_dir: str, verbose: bool = False) -> Dict[str, Any]:
    """Process a list of URLs and generate vulnerability reports.
    
    Args:
        urls: List of URLs to process
        output_dir: Directory to save output files
        verbose: Enable verbose logging
        
    Returns:
        Dictionary containing processing results and statistics
        
    Raises:
        ValueError: If urls list is empty
        FileNotFoundError: If output_dir doesn't exist
    """
    if not urls:
        raise ValueError("URLs list cannot be empty")
    
    results = {"processed": 0, "vulnerabilities": []}
    
    for url in urls:
        if verbose:
            click.echo(f"Processing: {url}")
        # Processing logic here
        results["processed"] += 1
    
    return results
```

### Module Structure

Each CLI module should follow this structure:

```python
#!/usr/bin/env python3
"""
Module description
"""

import click
from typing import List, Dict, Any
from pathlib import Path

# Helper functions

def helper_function() -> None:
    """Helper function docstring"""
    pass

# Main CLI command

@click.command()
@click.option("--input", "-i", required=True, help="Input file")
@click.option("--output-dir", "-o", default="output", help="Output directory")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def main(input: str, output_dir: str, verbose: bool) -> None:
    """Main command description"""
    pass

if __name__ == "__main__":
    main()
```

## 🧪 Testing

### Writing Tests

- Write unit tests for all new functions
- Add integration tests for CLI commands
- Use pytest fixtures for common test data
- Mock external dependencies

### Test Structure

```python
import pytest
from unittest.mock import patch, MagicMock

class TestYourModule:
    """Test class for your module"""
    
    def test_basic_functionality(self):
        """Test basic functionality"""
        # Test implementation
        pass
    
    @pytest.mark.slow
    def test_slow_operation(self):
        """Test that takes significant time"""
        pass
    
    @patch('subprocess.run')
    def test_external_command(self, mock_subprocess):
        """Test external command execution"""
        mock_subprocess.return_value.returncode = 0
        # Test implementation
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_vulncli.py

# Run with coverage
pytest --cov=reconcli

# Run only fast tests
pytest -m "not slow"

# Run only unit tests
pytest -m unit
```

## 📋 Pull Request Guidelines

### Before Submitting

- [ ] Code follows the style guidelines
- [ ] Tests pass locally
- [ ] New functionality includes tests
- [ ] Documentation is updated
- [ ] CHANGELOG is updated (for significant changes)

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

## 🐛 Reporting Issues

### Bug Reports

Include:
- ReconCLI version
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

### Feature Requests

Include:
- Clear description of the feature
- Use case and motivation
- Possible implementation approach
- Any relevant examples

## 🌟 VulnCLI Specific Guidelines

### AI Features Development

When contributing to AI-powered features in vulncli:

1. **Mock External APIs**: Don't make real API calls in tests
2. **Graceful Degradation**: Features should work without AI when APIs are unavailable
3. **Privacy Awareness**: Be mindful of data sent to external services
4. **Performance**: AI features should be optional and not slow down basic operations

### Security Tool Integration

When adding new security tools:

1. **Error Handling**: Tool may not be installed - handle gracefully
2. **Output Parsing**: Be robust with different tool versions
3. **Path Handling**: Use absolute paths and proper escaping
4. **Rate Limiting**: Respect tool limitations and target services

## 📚 Resources

- [Python Style Guide (PEP 8)](https://pep8.org/)
- [Click Documentation](https://click.palletsprojects.com/)
- [Pytest Documentation](https://docs.pytest.org/)
- [Type Hints (PEP 484)](https://peps.python.org/pep-0484/)

## 🏆 Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes for significant contributions
- GitHub contributor graphs

Thank you for contributing to ReconCLI! 🚀
