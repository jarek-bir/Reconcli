#!/usr/bin/env python3
"""
Base plugin class for file extractor plugins
"""

from abc import ABC, abstractmethod
from typing import Dict, Set, List, Any


class BasePlugin(ABC):
    """Base class for all extractor plugins"""
    
    def __init__(self):
        self.name = "Base Plugin"
        self.version = "1.0.0"
        self.patterns = {}
    
    @abstractmethod
    def extract(self, content: str, file_path: str) -> Dict[str, Set]:
        """Extract data from file content
        
        Args:
            content: File content as string
            file_path: Path to the file being analyzed
            
        Returns:
            Dictionary with extracted data as sets
        """
        pass
    
    def get_security_issues(self, extracted_data: Dict[str, Set]) -> List[Dict]:
        """Identify potential security issues from extracted data
        
        Args:
            extracted_data: Data extracted by the plugin
            
        Returns:
            List of security issue dictionaries
        """
        return []
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            "name": self.name,
            "version": self.version,
            "patterns_count": len(self.patterns)
        }
