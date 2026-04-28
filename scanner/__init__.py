"""
MCPGuard Scanner Engine
~~~~~~~~~~~~~~~~~~~~~~~
Security scanning modules for MCP servers.
"""

from scanner.dependency_audit import run_npm_audit, run_pip_audit, check_package_age, check_typosquatting, check_unpinned_dependencies
from scanner.static_analysis import scan_directory
from scanner.tool_analysis import extract_tool_definitions, analyze_tool_descriptions, check_unicode_tricks
from scanner.permission_audit import audit_permissions
from scanner.report_builder import build_report

__all__ = [
    "run_npm_audit",
    "run_pip_audit",
    "check_package_age",
    "check_typosquatting",
    "check_unpinned_dependencies",
    "scan_directory",
    "extract_tool_definitions",
    "analyze_tool_descriptions",
    "check_unicode_tricks",
    "audit_permissions",
    "build_report",
]
