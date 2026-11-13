"""
Project UMBRELLA - OpenTelemetry Astronomy Shop Demo Integration
AST & Call-Chain Inspector for OpenTelemetry Webstore Microservices
"""

import ast
import os
import re
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field


class StackFrameInfo(BaseModel):
    file_path: str
    line_number: int
    function_name: str
    code_context: Optional[str] = None
    frame_type: str = Field(default="unknown", description="'application', 'framework', or 'dependency'")


class CallChainAnalysis(BaseModel):
    total_frames: int = 0
    application_frames: List[StackFrameInfo] = Field(default_factory=list)
    top_application_frame: Optional[StackFrameInfo] = None
    deepest_failing_frame: Optional[StackFrameInfo] = None
    has_sql_signature: bool = False
    suspicious_injection_patterns: List[str] = Field(default_factory=list)


class ASTInspector:
    """Inspects microservice source code, configuration files, and stack traces."""

    @staticmethod
    def classify_frame_origin(file_path: str) -> str:
        """Classifies frame origin: application, framework, or dependency."""
        fp = file_path.replace("\\", "/").lower()
        if any(lib in fp for lib in ["site-packages", "node_modules", "vendor", "packages", "dist-packages"]):
            return "dependency"
        if any(fw in fp for fw in ["express", "fastapi", "gin-gonic", "grpc", "starlette", "next", "react"]):
            return "framework"
        if any(srv in fp for srv in ["checkout", "payment", "cart", "frontend", "currency", "recommendation", "catalog", "src/"]):
            return "application"
        return "application"

    @classmethod
    def detect_sql_injection_signatures(cls, text: str) -> List[str]:
        """Scans code snippets, tracebacks, and query text for common SQL injection attack signatures."""
        if not text:
            return []
        patterns = [
            (r"(?i)(\bUNION\b\s+\bSELECT\b)", "UNION-based SQL Injection attempt"),
            (r"(?i)(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)", "Boolean tautology SQL Injection (' OR '1'='1)"),
            (r"(?i)(;\s*DROP\s+TABLE)", "Stacked query DROP TABLE Injection"),
            (r"(--.*$|/\*.*?\*/)", "SQL comment inline truncation injection"),
            (r"(?i)(\bEXEC\b\s*\(|\bXP_CMDSHELL\b)", "Command execution injection attempt")
        ]
        detected = []
        for pat, desc in patterns:
            if re.search(pat, text, re.MULTILINE):
                detected.append(desc)
        return detected

    @classmethod
    def parse_stack_trace(cls, traceback_str: str) -> List[StackFrameInfo]:
        """Parses multi-language stack traces (Python, Node.js, Go) into structured frames."""
        frames: List[StackFrameInfo] = []
        if not traceback_str:
            return frames

        # Python pattern: File "path", line X, in func
        py_pattern = re.compile(r'File\s+"([^"]+)",\s+line\s+(\d+),\s+in\s+(\w+)')
        # Node.js pattern: at func (path:line:col) or at path:line:col
        node_pattern = re.compile(r'at\s+(?:([^\s(]+)\s+\()?(?:([A-Za-z]:[\\/][^:]+|/[^:]+|\./[^:]+|[^:\s]+)):(\d+):(?:\d+)\)?')
        # Go pattern: path/to/file.go:line +0x...
        go_pattern = re.compile(r'([^\s:]+\.go):(\d+)')

        lines = traceback_str.splitlines()
        for i, line in enumerate(lines):
            # Check Python
            m_py = py_pattern.search(line)
            if m_py:
                f_path, l_num, func = m_py.groups()
                ctx = lines[i + 1].strip() if i + 1 < len(lines) and not py_pattern.search(lines[i + 1]) else None
                frames.append(StackFrameInfo(
                    file_path=f_path,
                    line_number=int(l_num),
                    function_name=func,
                    code_context=ctx,
                    frame_type=cls.classify_frame_origin(f_path)
                ))
                continue

            # Check Node.js
            m_node = node_pattern.search(line)
            if m_node:
                func, f_path, l_num = m_node.groups()
                frames.append(StackFrameInfo(
                    file_path=f_path or "charge.js",
                    line_number=int(l_num),
                    function_name=func or "anonymous",
                    code_context=line.strip(),
                    frame_type=cls.classify_frame_origin(f_path or "")
                ))
                continue

            # Check Go
            m_go = go_pattern.search(line)
            if m_go:
                f_path, l_num = m_go.groups()
                frames.append(StackFrameInfo(
                    file_path=f_path,
                    line_number=int(l_num),
                    function_name="main",
                    code_context=line.strip(),
                    frame_type=cls.classify_frame_origin(f_path)
                ))

        return frames

    @classmethod
    def inspect_call_chain(cls, frames: List[StackFrameInfo], raw_text: str = "") -> CallChainAnalysis:
        """Inspects stack frames and detects application boundaries and SQL injection signatures."""
        analysis = CallChainAnalysis(total_frames=len(frames))
        analysis.application_frames = [f for f in frames if f.frame_type == "application"]

        if analysis.application_frames:
            analysis.top_application_frame = analysis.application_frames[0]
            analysis.deepest_failing_frame = analysis.application_frames[-1]

        # Scan frames and raw text
        for f in frames:
            if f.code_context:
                ctx_lower = f.code_context.lower()
                if any(k in ctx_lower for k in ["select", "insert", "update", "delete", "execute", "session", "cursor"]):
                    analysis.has_sql_signature = True
                injections = cls.detect_sql_injection_signatures(f.code_context)
                analysis.suspicious_injection_patterns.extend(injections)

        if raw_text:
            raw_injections = cls.detect_sql_injection_signatures(raw_text)
            analysis.suspicious_injection_patterns.extend(raw_injections)

        analysis.suspicious_injection_patterns = list(set(analysis.suspicious_injection_patterns))
        if analysis.suspicious_injection_patterns:
            analysis.has_sql_signature = True

        return analysis

    @staticmethod
    def _get_literal_value(node: ast.AST) -> Any:
        """Safely evaluates an AST literal value."""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.Str):
            return node.s
        elif isinstance(node, ast.Dict):
            res = {}
            for k, v in zip(node.keys, node.values):
                k_val = ASTInspector._get_literal_value(k)
                if k_val is not None:
                    res[k_val] = ASTInspector._get_literal_value(v)
            return res
        elif isinstance(node, (ast.List, ast.Tuple)):
            return [ASTInspector._get_literal_value(elt) for elt in node.elts]
        return None
