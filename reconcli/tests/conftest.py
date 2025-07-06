#!/usr/bin/env python3
"""
Pytest configuration for ReconCLI tests
"""

import pytest
import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def sample_urls():
    """Fixture providing sample URLs for testing"""
    return [
        "http://example.com",
        "https://example.com/path",
        "https://sub.example.com/path?param=value",
        "http://test.com/admin",
        "https://api.test.com/v1/endpoint",
    ]


@pytest.fixture
def temp_file_with_urls(tmp_path, sample_urls):
    """Fixture creating a temporary file with sample URLs"""
    temp_file = tmp_path / "test_urls.txt"
    temp_file.write_text("\n".join(sample_urls))
    return str(temp_file)


@pytest.fixture
def temp_output_dir(tmp_path):
    """Fixture creating a temporary output directory"""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return str(output_dir)


# Markers for different test types
pytest_plugins = []


def pytest_configure(config):
    """Configure pytest markers"""
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line(
        "markers", "integration: mark test as integration test requiring external tools"
    )
    config.addinivalue_line("markers", "unit: mark test as unit test")
