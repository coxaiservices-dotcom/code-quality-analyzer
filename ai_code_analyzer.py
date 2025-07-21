#!/usr/bin/env python3
"""
AI Code Quality Analyzer
A comprehensive tool for analyzing code quality in AI-generated code.
Focuses on common issues found in LLM-generated code including:
- Security vulnerabilities
- Performance anti-patterns
- Code style violations
- Logic errors
- Best practice violations
"""

import ast
import re
import os
import json
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import argparse


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Issue:
    """Represents a code quality issue."""
    rule_id: str
    severity: Severity
    message: str
    line_number: int
    column: int = 0
    suggestion: str = ""
    category: str = ""


class AICodeAnalyzer:
    """Main analyzer class for detecting AI-generated code issues."""
    
    def __init__(self):
        self.issues = []
        self.metrics = {
            'total_lines': 0,
            'complexity_score': 0,
            'security_issues': 0,
            'style_violations': 0,
            'performance_issues': 0
        }
    
    def analyze_file(self, file_path: str) -> List[Issue]:
        """Analyze a single Python file."""
        self.issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # Parse AST for structural analysis
            try:
                tree = ast.parse(code)
                self._analyze_ast(tree)
            except SyntaxError as e:
                self.issues.append(Issue(
                    rule_id="SYNTAX_ERROR",
                    severity=Severity.CRITICAL,
                    message=f"Syntax error: {e.msg}",
                    line_number=e.lineno or 1,
                    category="syntax"
                ))
            
            # Text-based analysis
            lines = code.split('\n')
            self.metrics['total_lines'] = len([l for l in lines if l.strip()])
            self._analyze_text_patterns(lines)
            
        except Exception as e:
            self.issues.append(Issue(
                rule_id="FILE_ERROR",
                severity=Severity.CRITICAL,
                message=f"Could not analyze file: {str(e)}",
                line_number=1,
                category="system"
            ))
        
        return self.issues
    
    def _analyze_ast(self, tree: ast.AST):
        """Analyze AST for structural issues common in AI-generated code."""
        
        class AICodeVisitor(ast.NodeVisitor):
            def __init__(self, analyzer):
                self.analyzer = analyzer
                self.function_depth = 0
                self.loop_depth = 0
            
            def visit_FunctionDef(self, node):
                self.function_depth += 1
                
                # Check for overly complex functions (AI tendency)
                if len(node.body) > 50:
                    self.analyzer.issues.append(Issue(
                        rule_id="COMPLEX_FUNCTION",
                        severity=Severity.MEDIUM,
                        message=f"Function '{node.name}' is too complex ({len(node.body)} statements)",
                        line_number=node.lineno,
                        suggestion="Consider breaking into smaller functions",
                        category="complexity"
                    ))
                
                # Check for missing docstrings
                if not ast.get_docstring(node):
                    self.analyzer.issues.append(Issue(
                        rule_id="MISSING_DOCSTRING",
                        severity=Severity.LOW,
                        message=f"Function '{node.name}' missing docstring",
                        line_number=node.lineno,
                        category="documentation"
                    ))
                
                # Check parameter count
                if len(node.args.args) > 7:
                    self.analyzer.issues.append(Issue(
                        rule_id="TOO_MANY_PARAMS",
                        severity=Severity.MEDIUM,
                        message=f"Function '{node.name}' has too many parameters ({len(node.args.args)})",
                        line_number=node.lineno,
                        suggestion="Consider using a configuration object",
                        category="design"
                    ))
                
                self.generic_visit(node)
                self.function_depth -= 1
            
            def visit_Try(self, node):
                # Check for overly broad exception handling (AI common mistake)
                for handler in node.handlers:
                    if handler.type is None or (isinstance(handler.type, ast.Name) and handler.type.id == 'Exception'):
                        self.analyzer.issues.append(Issue(
                            rule_id="BROAD_EXCEPTION",
                            severity=Severity.HIGH,
                            message="Catching too broad exceptions",
                            line_number=handler.lineno,
                            suggestion="Catch specific exception types",
                            category="error_handling"
                        ))
                
                self.generic_visit(node)
            
            def visit_Import(self, node):
                # Check for unused imports (AI often adds unnecessary imports)
                for alias in node.names:
                    if alias.name in ['os', 'sys', 'subprocess']:
                        self.analyzer.issues.append(Issue(
                            rule_id="POTENTIAL_SECURITY_IMPORT",
                            severity=Severity.MEDIUM,
                            message=f"Potentially dangerous import: {alias.name}",
                            line_number=node.lineno,
                            suggestion="Ensure secure usage of system modules",
                            category="security"
                        ))
                
                self.generic_visit(node)
            
            def visit_Call(self, node):
                # Check for dangerous function calls
                if isinstance(node.func, ast.Name):
                    if node.func.id == 'eval':
                        self.analyzer.issues.append(Issue(
                            rule_id="DANGEROUS_EVAL",
                            severity=Severity.CRITICAL,
                            message="Use of eval() is dangerous",
                            line_number=node.lineno,
                            suggestion="Use ast.literal_eval() for safe evaluation",
                            category="security"
                        ))
                    elif node.func.id == 'exec':
                        self.analyzer.issues.append(Issue(
                            rule_id="DANGEROUS_EXEC",
                            severity=Severity.CRITICAL,
                            message="Use of exec() is dangerous",
                            line_number=node.lineno,
                            category="security"
                        ))
                
                self.generic_visit(node)
            
            def visit_For(self, node):
                self.loop_depth += 1
                if self.loop_depth > 3:
                    self.analyzer.issues.append(Issue(
                        rule_id="DEEP_NESTING",
                        severity=Severity.MEDIUM,
                        message=f"Deep loop nesting (depth: {self.loop_depth})",
                        line_number=node.lineno,
                        suggestion="Consider extracting inner logic to functions",
                        category="complexity"
                    ))
                
                self.generic_visit(node)
                self.loop_depth -= 1
        
        visitor = AICodeVisitor(self)
        visitor.visit(tree)
    
    def _analyze_text_patterns(self, lines: List[str]):
        """Analyze text patterns that indicate AI-generated code issues."""
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Check for AI-common patterns
            if re.search(r'#\s*(TODO|FIXME|XXX|HACK)', line, re.IGNORECASE):
                self.issues.append(Issue(
                    rule_id="TODO_COMMENT",
                    severity=Severity.LOW,
                    message="Unresolved TODO/FIXME comment",
                    line_number=i,
                    category="maintenance"
                ))
            
            # Check for hardcoded credentials (AI sometimes includes examples)
            if re.search(r'(password|secret|key|token)\s*=\s*["\'][^"\']+["\']', line, re.IGNORECASE):
                self.issues.append(Issue(
                    rule_id="HARDCODED_CREDENTIALS",
                    severity=Severity.CRITICAL,
                    message="Potential hardcoded credentials detected",
                    line_number=i,
                    suggestion="Use environment variables or secure storage",
                    category="security"
                ))
            
            # Check for SQL injection patterns
            if re.search(r'(SELECT|INSERT|UPDATE|DELETE).*\+.*["\']', line, re.IGNORECASE):
                self.issues.append(Issue(
                    rule_id="SQL_INJECTION_RISK",
                    severity=Severity.HIGH,
                    message="Potential SQL injection vulnerability",
                    line_number=i,
                    suggestion="Use parameterized queries",
                    category="security"
                ))
            
            # Check for inefficient string concatenation
            if '+=' in line and ('str' in line.lower() or '"' in line or "'" in line):
                self.issues.append(Issue(
                    rule_id="INEFFICIENT_STRING_CONCAT",
                    severity=Severity.MEDIUM,
                    message="Inefficient string concatenation",
                    line_number=i,
                    suggestion="Use join() or f-strings for better performance",
                    category="performance"
                ))
            
            # Check line length
            if len(line) > 100:
                self.issues.append(Issue(
                    rule_id="LINE_TOO_LONG",
                    severity=Severity.LOW,
                    message=f"Line too long ({len(line)} chars)",
                    line_number=i,
                    category="style"
                ))
            
            # Check for print statements in production code
            if re.search(r'\bprint\s*\(', stripped) and not stripped.startswith('#'):
                self.issues.append(Issue(
                    rule_id="PRINT_STATEMENT",
                    severity=Severity.LOW,
                    message="Print statement found - consider using logging",
                    line_number=i,
                    suggestion="Replace with proper logging",
                    category="best_practices"
                ))
    
    def generate_report(self, output_format='text') -> str:
        """Generate analysis report."""
        if output_format == 'json':
            return self._generate_json_report()
        else:
            return self._generate_text_report()
    
    def _generate_text_report(self) -> str:
        """Generate human-readable text report."""
        report = []
        report.append("=" * 80)
        report.append("AI CODE QUALITY ANALYSIS REPORT")
        report.append("=" * 80)
        
        # Summary
        total_issues = len(self.issues)
        critical = len([i for i in self.issues if i.severity == Severity.CRITICAL])
        high = len([i for i in self.issues if i.severity == Severity.HIGH])
        medium = len([i for i in self.issues if i.severity == Severity.MEDIUM])
        low = len([i for i in self.issues if i.severity == Severity.LOW])
        
        report.append(f"\nSUMMARY:")
        report.append(f"Total Issues: {total_issues}")
        report.append(f"  Critical: {critical}")
        report.append(f"  High:     {high}")
        report.append(f"  Medium:   {medium}")
        report.append(f"  Low:      {low}")
        
        # Issues by category
        categories = {}
        for issue in self.issues:
            categories[issue.category] = categories.get(issue.category, 0) + 1
        
        if categories:
            report.append(f"\nISSUES BY CATEGORY:")
            for category, count in sorted(categories.items()):
                report.append(f"  {category.title()}: {count}")
        
        # Detailed issues
        if self.issues:
            report.append(f"\nDETAILED ISSUES:")
            report.append("-" * 40)
            
            for issue in sorted(self.issues, key=lambda x: (x.severity.value, x.line_number)):
                report.append(f"\nLine {issue.line_number}: [{issue.severity.value.upper()}] {issue.rule_id}")
                report.append(f"  Message: {issue.message}")
                if issue.suggestion:
                    report.append(f"  Suggestion: {issue.suggestion}")
        
        return "\n".join(report)
    
    def _generate_json_report(self) -> str:
        """Generate JSON report for programmatic use."""
        report = {
            'summary': {
                'total_issues': len(self.issues),
                'by_severity': {
                    'critical': len([i for i in self.issues if i.severity == Severity.CRITICAL]),
                    'high': len([i for i in self.issues if i.severity == Severity.HIGH]),
                    'medium': len([i for i in self.issues if i.severity == Severity.MEDIUM]),
                    'low': len([i for i in self.issues if i.severity == Severity.LOW])
                }
            },
            'issues': [
                {
                    **asdict(issue),
                    'severity': issue.severity.value
                }
                for issue in self.issues
            ],
            'metrics': self.metrics
        }
        return json.dumps(report, indent=2)


def main():
    parser = argparse.ArgumentParser(description='AI Code Quality Analyzer')
    parser.add_argument('file_path', help='Python file to analyze')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--output', '-o', help='Output file path (default: stdout)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file_path):
        print(f"Error: File '{args.file_path}' not found")
        return 1
    
    analyzer = AICodeAnalyzer()
    analyzer.analyze_file(args.file_path)
    
    report = analyzer.generate_report(args.format)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report written to {args.output}")
    else:
        print(report)
    
    # Return non-zero exit code if critical or high severity issues found
    critical_or_high = [i for i in analyzer.issues 
                       if i.severity in [Severity.CRITICAL, Severity.HIGH]]
    return 1 if critical_or_high else 0


if __name__ == '__main__':
    exit(main())