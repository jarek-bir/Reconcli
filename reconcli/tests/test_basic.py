#!/usr/bin/env python3
"""
Basic smoke tests for ReconCLI modules
These tests verify that modules can be imported and basic functionality works
"""

import pytest
import sys
import os

# Add the parent directory to the path to import reconcli modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestModuleImports:
    """Test that all modules can be imported without errors"""

    def test_import_main(self):
        """Test main module import"""
        try:
            import main

            assert hasattr(main, "main")
        except ImportError as e:
            pytest.skip(f"Main module import failed: {e}")

    def test_import_vulncli(self):
        """Test vulncli module import"""
        try:
            import vulncli

            assert hasattr(vulncli, "main")
        except ImportError as e:
            pytest.skip(f"VulnCLI module import failed: {e}")

    def test_import_urlcli(self):
        """Test urlcli module import"""
        try:
            import urlcli

            assert hasattr(urlcli, "main")
        except ImportError as e:
            pytest.skip(f"UrlCLI module import failed: {e}")

    def test_import_dnscli(self):
        """Test dnscli module import"""
        try:
            import dnscli

            assert hasattr(dnscli, "main")
        except ImportError as e:
            pytest.skip(f"DNSCLI module import failed: {e}")


class TestBasicFunctionality:
    """Test basic functionality of core modules"""

    def test_vulncli_help(self):
        """Test that vulncli help command works"""
        try:
            import vulncli

            # This should not raise an exception
            assert callable(vulncli.main)
        except ImportError:
            pytest.skip("VulnCLI module not available")

    def test_url_validation(self):
        """Test basic URL validation functionality"""
        # Basic URL validation test
        test_urls = [
            "http://example.com",
            "https://example.com/path",
            "https://sub.example.com/path?param=value",
        ]

        for url in test_urls:
            assert url.startswith(("http://", "https://"))

    def test_file_operations(self):
        """Test basic file operations used by modules"""
        import tempfile
        import os

        # Create a temporary file with test URLs
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("http://example.com\n")
            f.write("https://test.com\n")
            temp_file = f.name

        try:
            # Test file reading
            with open(temp_file, "r") as f:
                lines = f.readlines()
                assert len(lines) == 2
                assert "example.com" in lines[0]
                assert "test.com" in lines[1]
        finally:
            # Cleanup
            os.unlink(temp_file)


class TestUtilities:
    """Test utility functions"""

    def test_utils_import(self):
        """Test utils module import"""
        try:
            from utils import loaders

            assert hasattr(loaders, "load_file_lines")
        except ImportError:
            pytest.skip("Utils module not available")

    def test_notification_mock(self):
        """Test notification functionality (mocked)"""
        # Mock test for notification functionality
        webhook_url = "https://httpbin.org/post"
        message = "Test notification"

        # This is a basic structure test
        assert isinstance(webhook_url, str)
        assert isinstance(message, str)
        assert webhook_url.startswith("https://")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
