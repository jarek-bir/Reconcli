#!/usr/bin/env python3
"""
VHostHunter setup script
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="vhosthunter",
    version="1.0.0",
    author="Jarek",
    author_email="jarek@example.com",
    description="Professional virtual host discovery and security assessment tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jarek-bir/VHostHunter",
    project_urls={
        "Bug Reports": "https://github.com/jarek-bir/VHostHunter/issues",
        "Source": "https://github.com/jarek-bir/VHostHunter",
        "Documentation": "https://github.com/jarek-bir/VHostHunter/docs",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking :: Monitoring",
    ],
    keywords="vhost virtual-host discovery security bug-bounty penetration-testing",
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "httpx>=0.24.0",
        "requests>=2.28.0",
        "rich>=12.0.0",
        "sqlalchemy>=2.0.0",
    ],
    extras_require={
        "ai": ["openai>=0.27.0"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vhosthunter=vhosthunter:main",
        ],
    },
    include_package_data=True,
    package_data={
        "vhosthunter": [
            "wordlists/*.txt",
            "configs/*.json",
            "docs/*.md",
        ],
    },
    zip_safe=False,
)
