"""
Dig (Domain Information Groper) tool for DNS reconnaissance.

Features:
- DNS record lookups (A, AAAA, MX, NS, TXT, CNAME)
- Custom DNS server specification
- Support for trace and short output formats
- Structured output parsing

Safety Controls:
- Custom target validation to ensure valid domain names
- Whitelist of safe query types and flags
- Inherits all security features from MCPBaseTool (resource limits, etc.)
- Does not require intrusive operations to be enabled

Usage:
    tool = DigTool()
    
    # A record lookup
    result = await tool.run(ToolInput(
        target="example.com",
        extra_args="A"
    ))
    
    # MX record lookup using a specific DNS server
    result = await tool.run(ToolInput(
        target="gmail.com",
        extra_args="@8.8.8.8 MX"
    ))

Author: MCP Network Tools Team
Version: 1.0.0
"""

import logging
import re
import shlex
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone

from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput, ToolErrorType, ErrorContext

log = logging.getLogger(__name__)


class DigTool(MCPBaseTool):
    """
    Secure wrapper for the 'dig' DNS utility.
    
    This tool allows for safe, non-intrusive DNS reconnaissance. It validates
    that the target is a proper domain name and restricts operations to a
    whitelist of safe query types and flags.
    """
    
    command_name = "dig"
    
    # Whitelist of safe DNS query types and flags
    allowed_flags = [
        # Query Types
        "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA",
        # Common Flags
        "+short", "+trace", "+nocmd", "+noall", "+answer",
    ]
    
    # No flags that require values in the traditional sense, but the '@' syntax
    # for specifying a DNS server is handled separately.
    _FLAGS_REQUIRE_VALUE = {}
    
    # Timeout for DNS queries
    default_timeout_sec = 60.0
    
    # Concurrency
    concurrency = 5
    
    # Compiled patterns for performance
    _DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,6}$'
    )
    _ANSWER_SECTION_PATTERN = re.compile(
        r'^\s*;; ANSWER SECTION:\s*$.*?^$', re.MULTILINE | re.DOTALL
    )
    _ANSWER_LINE_PATTERN = re.compile(
        r'^(?P<name>\S+)\s+(?P<ttl>\d+)\s+(?P<class>\S+)\s+(?P<type>\S+)\s+(?P<value>.*)$'
    )

    async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute dig with custom domain validation."""
        # 1. Custom Target Validation
        if not self._validate_domain(inp.target):
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Invalid target: '{inp.target}' is not a valid domain name.",
                recovery_suggestion="Provide a valid, fully qualified domain name (e.g., 'example.com').",
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target
            )
            return self._create_error_output(error_context, inp.correlation_id or "")

        # 2. Custom Argument Validation
        try:
            validated_args = self._validate_dig_args(inp.extra_args or "")
        except ValueError as e:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=str(e),
                recovery_suggestion=f"Use allowed flags and query types: {', '.join(self.allowed_flags)}",
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target
            )
            return self._create_error_output(error_context, inp.correlation_id or "")

        # Create a new ToolInput with the validated arguments
        enhanced_input = ToolInput(
            target=inp.target,
            extra_args=validated_args,
            timeout_sec=timeout_sec or inp.timeout_sec or self.default_timeout_sec,
            correlation_id=inp.correlation_id,
        )

        # 3. Execute using the parent method
        result = await super()._execute_tool(enhanced_input, enhanced_input.timeout_sec)

        # 4. Parse Output
        if result.returncode == 0 and result.stdout:
            parsed_results = self._parse_dig_output(result.stdout)
            result.metadata['parsed_results'] = parsed_results
            result.metadata['answer_count'] = len(parsed_results)

        return result

    def _validate_domain(self, domain: str) -> bool:
        """Validate that the input is a well-formed domain name."""
        if not isinstance(domain, str) or len(domain) > 253:
            return False
        return bool(self._DOMAIN_PATTERN.match(domain))

    def _validate_dig_args(self, extra_args: str) -> str:
        """Validate dig-specific arguments, including the '@server' syntax."""
        tokens = shlex.split(extra_args) if extra_args else []
        validated_tokens = []

        for token in tokens:
            # Handle '@server' syntax
            if token.startswith('@'):
                server_name = token[1:]
                # Validate the server name as a domain or IP
                if not self._validate_domain(server_name):
                    try:
                        # Fallback to check if it's a valid IP address
                        import ipaddress
                        ipaddress.ip_address(server_name)
                    except ValueError:
                        raise ValueError(f"Invalid DNS server specified: '{server_name}'")
                validated_tokens.append(token)
            # Handle whitelisted flags and query types
            elif token in self.allowed_flags:
                validated_tokens.append(token)
            else:
                raise ValueError(f"Disallowed flag or query type: '{token}'")
        
        return " ".join(validated_tokens)

    def _parse_dig_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse the raw output of the dig command into a structured format."""
        results = []
        
        # Find the "ANSWER SECTION"
        answer_section_match = self._ANSWER_SECTION_PATTERN.search(output)
        if not answer_section_match:
            return results

        answer_section = answer_section_match.group(0)
        lines = answer_section.strip().split('\n')

        for line in lines:
            # Skip comments and the section header
            if line.startswith(';') or not line.strip():
                continue

            match = self._ANSWER_LINE_PATTERN.match(line)
            if match:
                results.append({
                    "name": match.group("name"),
                    "ttl": int(match.group("ttl")),
                    "class": match.group("class"),
                    "type": match.group("type"),
                    "value": match.group("value").strip(),
                })
        
        return results

    def _get_timestamp(self) -> datetime:
        """Get a timezone-aware timestamp."""
        return datetime.now(timezone.utc)

    def get_tool_info(self) -> Dict[str, Any]:
        """Get comprehensive tool information."""
        info = super().get_tool_info()
        info.update({
            "description": "Performs DNS lookups using the 'dig' utility.",
            "allowed_query_types": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"],
            "allowed_flags": ["+short", "+trace", "+nocmd", "+noall", "+answer"],
            "special_syntax": "Use '@server' to specify a DNS server (e.g., '@8.8.8.8').",
            "security_model": "Target must be a valid domain name. Only whitelisted flags and query types are permitted."
        })
        return info
