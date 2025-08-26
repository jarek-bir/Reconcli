#!/usr/bin/env python3
"""
Plugin manager for file extractor
"""

import os
import importlib
from typing import Dict, List, Any, Set
from pathlib import Path


class PluginManager:
    """Manage and coordinate extractor plugins"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.plugins = {}
        self.plugin_results = {}
        self.security_issues = []
    
    def log_verbose(self, message: str):
        """Log verbose messages"""
        if self.verbose:
            print(f"[PluginManager] {message}")
    
    def load_plugins(self):
        """Load all available plugins"""
        plugin_dir = Path(__file__).parent
        
        # Import plugins
        plugin_modules = {
            'aws': 'aws_extractor',
            'docker': 'docker_extractor', 
            'git': 'git_extractor',
            'network': 'network_extractor'
        }
        
        for plugin_name, module_name in plugin_modules.items():
            try:
                # Import the module
                module_path = f"plugins.{module_name}"
                module = importlib.import_module(module_path)
                
                # Get the plugin class (assumes ClassName = ModuleName with Extractor suffix)
                class_name = ''.join(word.capitalize() for word in module_name.split('_'))
                
                if hasattr(module, class_name):
                    plugin_class = getattr(module, class_name)
                    plugin_instance = plugin_class()
                    self.plugins[plugin_name] = plugin_instance
                    self.log_verbose(f"Loaded plugin: {plugin_instance.name}")
                else:
                    self.log_verbose(f"Warning: Plugin class {class_name} not found in {module_name}")
                    
            except ImportError as e:
                self.log_verbose(f"Failed to load plugin {plugin_name}: {e}")
            except Exception as e:
                self.log_verbose(f"Error loading plugin {plugin_name}: {e}")
    
    def extract_from_content(self, content: str, file_path: str) -> Dict[str, Any]:
        """Run all plugins on content and collect results"""
        if not self.plugins:
            self.load_plugins()
        
        all_results = {}
        
        for plugin_name, plugin in self.plugins.items():
            try:
                self.log_verbose(f"Running plugin: {plugin.name}")
                plugin_data = plugin.extract(content, file_path)
                
                if plugin_data:
                    # Store plugin results
                    all_results[f"{plugin_name}_data"] = plugin_data
                    
                    # Get security issues from plugin
                    security_issues = plugin.get_security_issues(plugin_data)
                    if security_issues:
                        for issue in security_issues:
                            issue['plugin'] = plugin_name
                            issue['file'] = file_path
                            self.security_issues.append(issue)
                
            except Exception as e:
                self.log_verbose(f"Error in plugin {plugin_name}: {e}")
        
        return all_results
    
    def get_plugin_info(self) -> List[Dict[str, Any]]:
        """Get information about loaded plugins"""
        if not self.plugins:
            self.load_plugins()
        
        return [plugin.get_info() for plugin in self.plugins.values()]
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get summary of all security issues found"""
        if not self.security_issues:
            return {"total_issues": 0, "by_severity": {}, "by_type": {}}
        
        severity_count = {}
        type_count = {}
        
        for issue in self.security_issues:
            severity = issue.get('severity', 'UNKNOWN')
            issue_type = issue.get('type', 'Unknown')
            
            severity_count[severity] = severity_count.get(severity, 0) + 1
            type_count[issue_type] = type_count.get(issue_type, 0) + 1
        
        return {
            "total_issues": len(self.security_issues),
            "by_severity": severity_count,
            "by_type": type_count,
            "issues": self.security_issues
        }
    
    def generate_security_report(self, output_dir: str):
        """Generate detailed security report"""
        os.makedirs(output_dir, exist_ok=True)
        
        security_summary = self.get_security_summary()
        
        # Save security issues as JSON
        import json
        with open(os.path.join(output_dir, "security_issues.json"), "w") as f:
            json.dump(security_summary, f, indent=2, ensure_ascii=False)
        
        # Generate human-readable security report
        report_path = os.path.join(output_dir, "security_report.txt")
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("SECURITY ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            total_issues = security_summary["total_issues"]
            f.write(f"🔍 Total Security Issues Found: {total_issues}\n\n")
            
            if total_issues == 0:
                f.write("✅ No security issues detected!\n")
                return
            
            # Summary by severity
            f.write("📊 ISSUES BY SEVERITY:\n")
            f.write("-" * 25 + "\n")
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
            for severity in severity_order:
                count = security_summary["by_severity"].get(severity, 0)
                if count > 0:
                    icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                    f.write(f"{icon} {severity}: {count} issues\n")
            f.write("\n")
            
            # Issues by type
            f.write("📋 ISSUES BY TYPE:\n")
            f.write("-" * 20 + "\n")
            for issue_type, count in sorted(security_summary["by_type"].items()):
                f.write(f"• {issue_type}: {count}\n")
            f.write("\n")
            
            # Detailed issues
            f.write("🔍 DETAILED SECURITY ISSUES:\n")
            f.write("-" * 30 + "\n\n")
            
            current_severity = None
            for issue in sorted(security_summary["issues"], 
                              key=lambda x: (severity_order.index(x.get('severity', 'UNKNOWN')), x.get('type', ''))):
                
                severity = issue.get('severity', 'UNKNOWN')
                if severity != current_severity:
                    current_severity = severity
                    icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                    f.write(f"\n{icon} {severity} SEVERITY ISSUES:\n")
                    f.write("─" * 40 + "\n")
                
                f.write(f"\n📍 {issue.get('type', 'Unknown Issue')}\n")
                f.write(f"   File: {issue.get('file', 'Unknown')}\n")
                f.write(f"   Plugin: {issue.get('plugin', 'Unknown')}\n")
                f.write(f"   Description: {issue.get('description', 'No description')}\n")
                if issue.get('count'):
                    f.write(f"   Count: {issue['count']}\n")
                f.write(f"   💡 Recommendation: {issue.get('recommendation', 'No recommendation provided')}\n")
        
        self.log_verbose(f"Security report saved to: {report_path}")


# Standalone functions for plugins
def load_plugin_dynamically(plugin_name: str, module_name: str):
    """Dynamically load a plugin"""
    try:
        module = importlib.import_module(f"plugins.{module_name}")
        class_name = ''.join(word.capitalize() for word in module_name.split('_'))
        if hasattr(module, class_name):
            return getattr(module, class_name)()
        return None
    except ImportError:
        return None
