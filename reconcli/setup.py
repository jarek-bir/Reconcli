#!/usr/bin/env python3
"""
ReconCLI - Modular Reconnaissance Toolkit
Setup configuration for package installation and distribution.
"""

from setuptools import setup, find_packages
import os


# Read README for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    try:
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "A comprehensive, modular reconnaissance toolkit for security professionals."


# Read requirements
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
    try:
        with open(requirements_path, "r", encoding="utf-8") as f:
            requirements = []
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    requirements.append(line)
            return requirements
    except FileNotFoundError:
        return [
            "click>=8.0.0",
            "requests>=2.28.0",
            "pyyaml>=6.0",
            "aiohttp>=3.8.0",
            "asyncio-throttle>=1.0.0",
        ]


setup(
    name="reconcli",
    version="3.0.0",
    description="A comprehensive, modular reconnaissance toolkit for security professionals and bug bounty hunters",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="Jarek Bir",
    author_email="jarek.bir@example.com",  # Replace with actual email
    url="https://github.com/jarek-bir/Reconcli",
    project_urls={
        "Bug Reports": "https://github.com/jarek-bir/Reconcli/issues",
        "Source": "https://github.com/jarek-bir/Reconcli",
        "Documentation": "https://github.com/jarek-bir/Reconcli/wiki",
    },
    packages=find_packages(),
    include_package_data=True,
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "flake8>=5.0.0",
            "bandit>=1.7.0",
            "mypy>=1.0.0",
        ],
        "ai": ["openai>=1.0.0", "anthropic>=0.8.0"],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="security, reconnaissance, pentesting, bug-bounty, vulnerability-scanning, ai-powered",
    entry_points={
        "console_scripts": [
            "reconcli=reconcli.main:main",
        ],
    },
    package_data={
        "reconcli": ["flows/*.yaml", "gf_patterns/*", "wordlists/*.txt", "utils/*.py"]
    },
    zip_safe=False,
)
