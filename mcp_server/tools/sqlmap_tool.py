"""
SQLmap SQL injection detection and exploitation tool with comprehensive safety controls.

Features:
- Automated SQL injection detection and exploitation
- Database enumeration and data extraction
- Multiple injection technique support
- Risk and test level controls
- Batch mode enforcement for non-interactive operation
- Comprehensive URL validation

Security Controls:
- CRITICAL: Only use on authorized systems
- Risk level limits (max 2)
- Test level limits (max 3)
- Thread count restrictions
- URL hostname authorization (RFC1918/lab.internal)
- Batch mode enforcement
- Technique filtering

WARNING:
    This is a SQL injection tool intended ONLY for authorized
    security testing. Unauthorized use is illegal and unethical.
    
    Use only on systems you own or have explicit permission to test.
    
    SQLmap performs active database attacks which can:
    - Modify database contents
    - Extract sensitive data
    - Trigger security alerts
    - Cause database performance issues
    - Result in legal consequences if misused

Usage:
    tool = SqlmapTool()
    
    # Basic SQL injection test
    result = await tool.run(ToolInput(
        target="192.168.1.10",
        extra_args="-u http://192.168.1.10/page.php?id=1 --batch --risk=1 --level=1"
    ))
    
    # Database enumeration
    result = await tool.run(ToolInput(
        target="192.168.1.10",
        extra_args="-u http://192.168.1.10/page.php?id=1 --batch --risk=2 --level=2 --dbs"
    ))
    
    # Table enumeration
    result = await tool.run(ToolInput(
        target="192.168.1.10",
        extra_args="-u http://192.168.1.10/page.php?id=1 --batch -D testdb --tables"
    ))

Configuration:
    # config.yaml
    tool:
      default_timeout: 1800  # 30 minutes
      default_concurrency: 1
    
    circuit_breaker:
      failure_threshold: 3
      recovery_timeout: 300.0

Environment Variables:
    MCP_DEFAULT_TIMEOUT_SEC: Override default timeout
    MCP_DEFAULT_CONCURRENCY: Override concurrency (forced to 1)

Author: MCP Network Tools Team
Version: 2.0.0
"""

import logging
import re
import shlex
from typing import ClassVar, Optional, Sequence, Dict, Any, Tuple
from urllib.parse import urlparse
from datetime import datetime, timezone

from mcp_server.base_tool import MCPBaseTool, ToolInput, ToolOutput, ToolErrorType, ErrorContext
from mcp_server.config import get_config

log = logging.getLogger(__name__)


class SqlmapTool(MCPBaseTool):
    """
    SQLmap SQL injection detection and exploitation tool with comprehensive safety controls.
    
    SQLmap is an automated tool for detecting and exploiting SQL injection
    vulnerabilities. This wrapper adds strict safety controls for authorized
    security testing.
    
    Command Structure:
        sqlmap [OPTIONS]
        
        OPTIONS must include: -u <URL> --batch
        URL is in extra_args, target is just hostname/IP
    
    Security Model:
        - Risk level limits (1-2 only)
        - Test level limits (1-3 only)
        - Thread count restrictions (max 10)
        - URL hostname authorization (RFC1918/lab.internal)
        - Batch mode enforcement
        - Technique filtering (safe subset)
    
    Attributes:
        command_name: System command (sqlmap)
        allowed_flags: Whitelist of permitted flags
        default_timeout_sec: Default timeout (1800s / 30 minutes)
        concurrency: Max concurrent executions (1 - exclusive)
    
    Example:
        >>> tool = SqlmapTool()
        >>> result = await tool.run(ToolInput(
        ...     target="192.168.1.10",
        ...     extra_args="-u http://192.168.1.10/page.php?id=1 --batch"
        ... ))
    """
    
    command_name: ClassVar[str] = "sqlmap"
    
    # Security limits (constants)
    MAX_RISK_LEVEL = 2
    MAX_TEST_LEVEL = 3
    DEFAULT_THREADS = 5
    MAX_THREADS = 10
    DEFAULT_TIME_SEC = 5
    
    # Allowed SQL injection techniques (safe subset)
    # B=Boolean, E=Error, U=Union, S=Stacked, T=Time-based
    ALLOWED_TECHNIQUES = frozenset(['B', 'E', 'U', 'S', 'T'])
    
    # Allowed flags (comprehensive whitelist)
    allowed_flags: ClassVar[Sequence[str]] = [
        # Target specification (required)
        "-u", "--url",
        
        # Operation mode (required for safety)
        "--batch",
        
        # Risk and test level control
        "--risk", "--level",
        
        # Database/table/column specification
        "-D", "--database",
        "-T", "--table",
        "-C", "--column",
        
        # Enumeration flags
        "--dbs",                    # List databases
        "--tables",                 # List tables
        "--columns",                # List columns
        "--dump",                   # Dump table contents
        "--dump-all",              # Dump all tables
        "--current-user",          # Get current user
        "--current-db",            # Get current database
        "--users",                 # List users
        "--passwords",             # List password hashes
        "--roles",                 # List roles
        "--privileges",            # List privileges
        "--schema",                # Database schema
        
        # Technique control
        "--technique",             # SQL injection techniques to use
        
        # Timing control
        "--time-sec",              # Time-based delay (seconds)
        
        # Performance control
        "--threads",               # Number of threads
        
        # HTTP options
        "--cookie",                # HTTP cookie
        "--user-agent",            # HTTP user agent
        "--referer",               # HTTP referer
        "--headers",               # Additional HTTP headers
        "--method",                # HTTP method (GET/POST)
        "--data",                  # POST data
        
        # Union technique options
        "--union-cols",            # Union column count
        "--union-char",            # Union character
        
        # Output control
        "--output-dir",            # Output directory
        "--flush-session",         # Flush session
        "--fresh-queries",         # Fresh queries
        
        # Format control
        "--json",                  # JSON output format
        
        # Detection
        "--string",                # String to match (true positive)
        "--not-string",            # String to match (false positive)
        "--regexp",                # Regexp to match (true positive)
        
        # Optimization
        "--skip",                  # Skip testing parameters
        "--skip-static",           # Skip static parameters
        
        # Safety
        "--safe-url",              # Safe URL for session checking
        "--safe-freq",             # Safe URL request frequency
    ]
    
    # Flags that require values
    _FLAGS_REQUIRE_VALUE = frozenset({
        "-u", "--url",
        "--risk", "--level",
        "-D", "--database",
        "-T", "--table",
        "-C", "--column",
        "--technique",
        "--time-sec",
        "--threads",
        "--cookie",
        "--user-agent",
        "--referer",
        "--headers",
        "--method",
        "--data",
        "--union-cols",
        "--union-char",
        "--output-dir",
        "--string",
        "--not-string",
        "--regexp",
        "--skip",
        "--safe-url",
        "--safe-freq",
    })
    
    # Timeouts (SQL injection testing is long-running)
    default_timeout_sec: ClassVar[float] = 1800.0  # 30 minutes
    
    # Concurrency (EXCLUSIVE - only one sqlmap at a time)
    concurrency: ClassVar[int] = 1
    
    # Circuit breaker (strict for attack tools)
    circuit_breaker_failure_threshold: ClassVar[int] = 3
    circuit_breaker_recovery_timeout: ClassVar[float] = 300.0
    circuit_breaker_expected_exception: ClassVar[tuple] = (Exception,)
    
    # Compiled patterns for validation
    _URL_SAFE_PATTERN = re.compile(r'^[A-Za-z0-9_:/\-\.\?=&%#]+$')
    _PARAM_PATTERN = re.compile(r'Parameter:\s+(\S+)\s+\((\w+)\)', re.MULTILINE)
    _TYPE_PATTERN = re.compile(r'Type:\s+(.+)', re.MULTILINE)
    _DBMS_PATTERN = re.compile(r'back-end DBMS[:\s]+(\w+)', re.IGNORECASE | re.MULTILINE)
    _DB_LIST_PATTERN = re.compile(r'\[\*\]\s+(.+)', re.MULTILINE)
    
    def __init__(self):
        """Initialize SQLmap tool with strict safety controls."""
        super().__init__()
        self.config = get_config()
        self._apply_config()
        
        log.info("sqlmap_tool.initialized timeout=%.1f AUTHORIZED_USE_ONLY",
                self.default_timeout_sec)
        log.warning("sqlmap_tool.WARNING attack_tool authorized_systems_only")
    
    def _apply_config(self):
        """Apply configuration settings with strict safety enforcement."""
        try:
            # Apply circuit breaker config
            if hasattr(self.config, 'circuit_breaker') and self.config.circuit_breaker:
                cb = self.config.circuit_breaker
                if hasattr(cb, 'failure_threshold'):
                    original = self.circuit_breaker_failure_threshold
                    self.circuit_breaker_failure_threshold = max(1, min(10, int(cb.failure_threshold)))
                    if self.circuit_breaker_failure_threshold != original:
                        log.info("sqlmap.config_clamped param=failure_threshold original=%d new=%d",
                                original, self.circuit_breaker_failure_threshold)
                
                if hasattr(cb, 'recovery_timeout'):
                    original = self.circuit_breaker_recovery_timeout
                    self.circuit_breaker_recovery_timeout = max(60.0, min(600.0, float(cb.recovery_timeout)))
                    if self.circuit_breaker_recovery_timeout != original:
                        log.info("sqlmap.config_clamped param=recovery_timeout original=%.1f new=%.1f",
                                original, self.circuit_breaker_recovery_timeout)
            
            # Apply tool config
            if hasattr(self.config, 'tool') and self.config.tool:
                tool = self.config.tool
                if hasattr(tool, 'default_timeout'):
                    original = self.default_timeout_sec
                    self.default_timeout_sec = max(60.0, min(3600.0, float(tool.default_timeout)))
                    if self.default_timeout_sec != original:
                        log.info("sqlmap.config_clamped param=default_timeout original=%.1f new=%.1f",
                                original, self.default_timeout_sec)
                
                # Force concurrency to 1 for sqlmap
                self.concurrency = 1
            
            log.debug("sqlmap.config_applied timeout=%.1f concurrency=%d",
                     self.default_timeout_sec, self.concurrency)
            
        except Exception as e:
            log.error("sqlmap.config_apply_failed error=%s using_safe_defaults", str(e))
            # Reset to safe defaults
            self.circuit_breaker_failure_threshold = 3
            self.circuit_breaker_recovery_timeout = 300.0
            self.default_timeout_sec = 1800.0
            self.concurrency = 1
    
    async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
        """Execute sqlmap with comprehensive validation and safety checks."""
        # Step 1: SQLmap-specific validation
        validation_error = self._validate_sqlmap_requirements(inp)
        if validation_error:
            return validation_error
        
        # Step 2: Parse and validate arguments
        try:
            validated_args = self._parse_and_validate_args(inp.extra_args or "", inp.target)
        except ValueError as e:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Invalid arguments: {str(e)}",
                recovery_suggestion="Check argument syntax, URL format, and risk/level limits",
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"error": str(e), "provided_args": inp.extra_args}
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Step 3: Optimize arguments with safety defaults
        optimized_args = self._optimize_sqlmap_args(validated_args)
        
        # Step 4: Create enhanced input
        enhanced_input = ToolInput(
            target=inp.target,
            extra_args=optimized_args,
            timeout_sec=timeout_sec or inp.timeout_sec or self.default_timeout_sec,
            correlation_id=inp.correlation_id
        )
        
        log.warning("sqlmap.executing target=%s AUTHORIZED_TESTING_ONLY args=%s",
                   inp.target, optimized_args)
        
        # Step 5: Execute with base class
        result = await super()._execute_tool(enhanced_input, enhanced_input.timeout_sec)
        
        # Step 6: Parse output for vulnerabilities
        if result.returncode == 0 or result.stdout:
            try:
                parsed_results = self._parse_sqlmap_output(result.stdout)
                result.ensure_metadata()
                result.metadata['parsed_results'] = parsed_results
                result.metadata['vulnerable'] = parsed_results.get('vulnerable', False)
                result.metadata['injection_types'] = len(parsed_results.get('injection_types', []))
                
                log.info("sqlmap.execution_completed vulnerable=%s injection_types=%d",
                        parsed_results.get('vulnerable', False),
                        len(parsed_results.get('injection_types', [])))
            except Exception as e:
                log.warning("sqlmap.parse_failed error=%s", str(e))
                # Don't fail on parse errors
        
        return result
    
    def _validate_sqlmap_requirements(self, inp: ToolInput) -> Optional[ToolOutput]:
        """
        Validate sqlmap-specific requirements.
        
        Checks:
        - URL presence in -u flag
        - URL format validation
        - URL hostname authorization
        
        Args:
            inp: Tool input
        
        Returns:
            ToolOutput with error if validation fails, None otherwise
        """
        # Extract URL from -u flag
        url = self._extract_url_from_args(inp.extra_args or "")
        if not url:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message="SQLmap requires -u/--url flag with target URL",
                recovery_suggestion=(
                    "Add -u flag with target URL:\n"
                    "  -u http://192.168.1.10/page.php?id=1\n"
                    "  -u http://target.lab.internal/login.php?user=admin"
                ),
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={
                    "example": "-u http://192.168.1.10/page.php?id=1 --batch",
                    "provided_args": inp.extra_args
                }
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Validate URL format
        if not self._is_valid_url_format(url):
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Invalid URL format: {url}",
                recovery_suggestion=(
                    "Use valid URL format:\n"
                    "  http://192.168.1.10/page.php?id=1\n"
                    "  https://target.lab.internal/login.php?user=admin\n"
                    "URL must have scheme (http/https) and hostname"
                ),
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"url": url}
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Extract and validate hostname
        hostname = self._extract_hostname(url)
        if not hostname:
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"Cannot extract hostname from URL: {url}",
                recovery_suggestion="Ensure URL has valid hostname (e.g., http://192.168.1.10/page.php)",
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={"url": url}
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        # Validate hostname is authorized
        if not self._is_authorized_hostname(hostname):
            error_context = ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message=f"URL hostname not authorized: {hostname}",
                recovery_suggestion=(
                    "URL hostname must be:\n"
                    "  - RFC1918 private IP (10.x.x.x, 172.16-31.x.x, 192.168.x.x)\n"
                    "  - .lab.internal domain (e.g., target.lab.internal)"
                ),
                timestamp=self._get_timestamp(),
                tool_name=self.tool_name,
                target=inp.target,
                metadata={
                    "url": url,
                    "hostname": hostname,
                    "examples": ["http://192.168.1.10/page.php", "http://server.lab.internal/app"]
                }
            )
            return self._create_error_output(error_context, inp.correlation_id or "")
        
        log.debug("sqlmap.requirements_validated url=%s hostname=%s", url, hostname)
        
        return None
    
    def _extract_url_from_args(self, extra_args: str) -> Optional[str]:
        """
        Extract URL from -u/--url flag in arguments.
        
        Args:
            extra_args: Extra arguments string
        
        Returns:
            URL string or None if not found
        """
        try:
            tokens = shlex.split(extra_args)
            for i, token in enumerate(tokens):
                if token in ("-u", "--url"):
                    if i + 1 < len(tokens):
                        return tokens[i + 1]
        except ValueError as e:
            log.debug("sqlmap.url_extraction_failed error=%s", str(e))
        
        return None
    
    def _is_valid_url_format(self, url: str) -> bool:
        """
        Validate URL has proper format.
        
        Args:
            url: URL to validate
        
        Returns:
            True if valid format, False otherwise
        """
        try:
            parsed = urlparse(url)
            # Must have scheme (http/https) and netloc (hostname)
            return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
        except Exception:
            return False
    
    def _extract_hostname(self, url: str) -> Optional[str]:
        """
        Extract hostname from URL.
        
        Args:
            url: URL to extract from
        
        Returns:
            Hostname string or None
        """
        try:
            return urlparse(url).hostname
        except Exception:
            return None
    
    def _is_authorized_hostname(self, hostname: str) -> bool:
        """
        Check if hostname is RFC1918 or .lab.internal.
        
        Args:
            hostname: Hostname to check
        
        Returns:
            True if authorized, False otherwise
        """
        if not hostname:
            return False
        
        # Check .lab.internal
        if hostname.endswith('.lab.internal'):
            return True
        
        # Check RFC1918
        try:
            import ipaddress
            ip = ipaddress.ip_address(hostname)
            return ip.version == 4 and ip.is_private
        except ValueError:
            # Not an IP address, must end with .lab.internal
            return False
    
    def _parse_and_validate_args(self, extra_args: str, target: str) -> str:
        """
        Parse and validate arguments.
        
        Args:
            extra_args: Extra arguments string
            target: Target hostname/IP for validation context
        
        Returns:
            Validated arguments string
        
        Raises:
            ValueError: If validation fails
        """
        if not extra_args:
            raise ValueError("SQLmap requires arguments (-u URL --batch)")
        
        try:
            tokens = shlex.split(extra_args)
        except ValueError as e:
            raise ValueError(f"Failed to parse arguments: {str(e)}")
        
        validated = []
        i = 0
        
        while i < len(tokens):
            token = tokens[i]
            
            # Block non-flag tokens (except for values)
            if not token.startswith("-"):
                # Check if this is a value for previous flag
                if i > 0 and tokens[i - 1].startswith("-"):
                    flag = tokens[i - 1].split("=")[0]
                    if flag in self._FLAGS_REQUIRE_VALUE:
                        # This is handled in flag processing below
                        i += 1
                        continue
                
                raise ValueError(
                    f"Unexpected non-flag token: '{token}'\n"
                    f"Flags must start with '-'"
                )
            
            # Handle flags
            flag_base = token.split("=")[0]
            
            if flag_base not in self.allowed_flags:
                raise ValueError(f"Flag not allowed: {token}")
            
            # Check if flag requires value
            if flag_base in self._FLAGS_REQUIRE_VALUE:
                if i + 1 >= len(tokens):
                    raise ValueError(f"{flag_base} requires a value")
                
                value = tokens[i + 1]
                
                # Validate specific flags
                if flag_base == "--risk":
                    # Risk level validation
                    try:
                        risk = int(value)
                        if not (1 <= risk <= self.MAX_RISK_LEVEL):
                            raise ValueError(
                                f"Risk level must be 1-{self.MAX_RISK_LEVEL}, got: {risk}"
                            )
                    except ValueError as e:
                        if "must be" in str(e):
                            raise
                        raise ValueError(f"Invalid risk level: {value}")
                
                elif flag_base == "--level":
                    # Test level validation
                    try:
                        level = int(value)
                        if not (1 <= level <= self.MAX_TEST_LEVEL):
                            raise ValueError(
                                f"Test level must be 1-{self.MAX_TEST_LEVEL}, got: {level}"
                            )
                    except ValueError as e:
                        if "must be" in str(e):
                            raise
                        raise ValueError(f"Invalid test level: {value}")
                
                elif flag_base == "--threads":
                    # Thread count validation
                    try:
                        threads = int(value)
                        if not (1 <= threads <= self.MAX_THREADS):
                            raise ValueError(
                                f"Thread count must be 1-{self.MAX_THREADS}, got: {threads}"
                            )
                    except ValueError as e:
                        if "must be" in str(e):
                            raise
                        raise ValueError(f"Invalid thread count: {value}")
                
                elif flag_base == "--time-sec":
                    # Time delay validation
                    try:
                        time_sec = int(value)
                        if time_sec < 1 or time_sec > 30:
                            raise ValueError(
                                f"Time delay must be 1-30 seconds, got: {time_sec}"
                            )
                    except ValueError as e:
                        if "must be" in str(e):
                            raise
                        raise ValueError(f"Invalid time delay: {value}")
                
                elif flag_base == "--technique":
                    # Technique validation
                    for char in value.upper():
                        if char not in self.ALLOWED_TECHNIQUES:
                            raise ValueError(
                                f"Technique '{char}' not allowed. "
                                f"Allowed: {', '.join(sorted(self.ALLOWED_TECHNIQUES))}"
                            )
                
                elif flag_base in ("-u", "--url"):
                    # URL validation (safe characters)
                    if not self._is_safe_url_token(value):
                        raise ValueError(
                            f"URL contains unsafe characters or path traversal: {value}"
                        )
                
                validated.extend([token, value])
                i += 2
            else:
                # Boolean flag (no value required)
                validated.append(token)
                i += 1
        
        result = " ".join(validated)
        
        log.debug("sqlmap.args_validated args_count=%d", len(validated))
        
        return result
    
    def _is_safe_url_token(self, token: str) -> bool:
        """
        Validate URL tokens are safe.
        
        Args:
            token: Token to validate
        
        Returns:
            True if safe, False otherwise
        """
        # Block path traversal
        if ".." in token:
            return False
        
        # Allow URL-safe characters
        # Includes: alphanumeric, :, /, -, _, ., ?, =, &, %, #
        return bool(self._URL_SAFE_PATTERN.match(token))
    
    def _optimize_sqlmap_args(self, validated_args: str) -> str:
        """
        Add safety defaults without overriding user choices.
        
        Adds:
        - --batch (non-interactive mode)
        - Default risk level (1)
        - Default test level (1)
        - Default thread count (5)
        
        Args:
            validated_args: Validated arguments string
        
        Returns:
            Optimized arguments string
        """
        try:
            tokens = shlex.split(validated_args) if validated_args else []
        except ValueError:
            tokens = validated_args.split() if validated_args else []
        
        optimized = []
        
        # Check what's present
        has_batch = "--batch" in tokens
        has_risk = "--risk" in tokens
        has_level = "--level" in tokens
        has_threads = "--threads" in tokens
        
        # Add safety defaults only if missing
        if not has_batch:
            optimized.append("--batch")
            log.debug("sqlmap.optimization added=batch")
        
        if not has_risk:
            optimized.extend(["--risk", "1"])
            log.debug("sqlmap.optimization added=risk value=1")
        
        if not has_level:
            optimized.extend(["--level", "1"])
            log.debug("sqlmap.optimization added=level value=1")
        
        if not has_threads:
            optimized.extend(["--threads", str(self.DEFAULT_THREADS)])
            log.debug("sqlmap.optimization added=threads value=%d", self.DEFAULT_THREADS)
        
        # Add original arguments
        optimized.extend(tokens)
        
        result = " ".join(optimized)
        
        if len(optimized) != len(tokens):
            log.info("sqlmap.arguments_optimized original=%d optimized=%d",
                    len(tokens), len(optimized))
        
        return result
    
    def _parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """
        Parse SQLmap output for found vulnerabilities.
        
        SQLmap output patterns:
        - "Parameter: id (GET)"
        - "Type: boolean-based blind"
        - "Title: AND boolean-based blind - WHERE or HAVING clause"
        - "[INFO] the back-end DBMS is MySQL"
        - "available databases [3]:"
        
        Args:
            output: Raw SQLmap output
        
        Returns:
            Dictionary with parsed vulnerability results
        """
        results = {
            "vulnerable": False,
            "parameters": [],
            "injection_types": [],
            "dbms": None,
            "databases": [],
            "summary": {}
        }
        
        # Check if vulnerable
        if any(phrase in output for phrase in [
            "is vulnerable",
            "sqlmap identified",
            "injectable",
            "exploit",
        ]):
            results["vulnerable"] = True
        
        # Extract vulnerable parameters
        for match in self._PARAM_PATTERN.finditer(output):
            param_info = {
                "name": match.group(1),
                "type": match.group(2)  # GET, POST, etc.
            }
            if param_info not in results["parameters"]:
                results["parameters"].append(param_info)
        
        # Extract injection types
        for match in self._TYPE_PATTERN.finditer(output):
            inj_type = match.group(1).strip()
            if inj_type and inj_type not in results["injection_types"]:
                results["injection_types"].append(inj_type)
        
        # Extract DBMS
        dbms_match = self._DBMS_PATTERN.search(output)
        if dbms_match:
            results["dbms"] = dbms_match.group(1)
        
        # Extract databases if enumerated
        if "available databases" in output.lower():
            # Find database count
            db_count_pattern = re.compile(r'available databases \[(\d+)\]:', re.IGNORECASE)
            db_count_match = db_count_pattern.search(output)
            if db_count_match:
                results["summary"]["database_count"] = int(db_count_match.group(1))
            
            # Parse database list
            for match in self._DB_LIST_PATTERN.finditer(output):
                db_name = match.group(1).strip()
                if db_name and db_name not in results["databases"]:
                    results["databases"].append(db_name)
        
        # Extract current user
        current_user_pattern = re.compile(r'current user:\s*[\'"]?([^\'"]+)[\'"]?', re.IGNORECASE)
        user_match = current_user_pattern.search(output)
        if user_match:
            results["summary"]["current_user"] = user_match.group(1).strip()
        
        # Extract current database
        current_db_pattern = re.compile(r'current database:\s*[\'"]?([^\'"]+)[\'"]?', re.IGNORECASE)
        db_match = current_db_pattern.search(output)
        if db_match:
            results["summary"]["current_db"] = db_match.group(1).strip()
        
        log.debug("sqlmap.output_parsed vulnerable=%s parameters=%d injection_types=%d",
                 results["vulnerable"], len(results["parameters"]), len(results["injection_types"]))
        
        return results
    
    def _get_timestamp(self) -> datetime:
        """
        Get current timestamp with timezone.
        
        Returns:
            Current UTC timestamp
        """
        return datetime.now(timezone.utc)
    
    def get_tool_info(self) -> Dict[str, Any]:
        """
        Get comprehensive tool information.
        
        Returns:
            Dictionary with complete tool metadata including security
            restrictions and usage examples
        """
        base_info = super().get_tool_info()
        
        sqlmap_info = {
            "sqlmap_specific": {
                "security_limits": {
                    "max_risk_level": self.MAX_RISK_LEVEL,
                    "max_test_level": self.MAX_TEST_LEVEL,
                    "default_threads": self.DEFAULT_THREADS,
                    "max_threads": self.MAX_THREADS,
                    "default_time_sec": self.DEFAULT_TIME_SEC,
                },
                
                "allowed_techniques": sorted(list(self.ALLOWED_TECHNIQUES)),
                "technique_descriptions": {
                    "B": "Boolean-based blind",
                    "E": "Error-based",
                    "U": "Union query-based",
                    "S": "Stacked queries",
                    "T": "Time-based blind"
                },
                
                "safety_features": [
                    "Risk level limits (max 2)",
                    "Test level limits (max 3)",
                    "Thread count restrictions (max 10)",
                    "URL hostname authorization (RFC1918/lab.internal)",
                    "Batch mode enforcement (non-interactive)",
                    "Technique filtering (safe subset)",
                    "URL validation and sanitization",
                ],
                
                "enumeration_capabilities": {
                    "databases": "--dbs",
                    "tables": "--tables",
                    "columns": "--columns",
                    "data_dump": "--dump",
                    "current_user": "--current-user",
                    "current_db": "--current-db",
                    "users": "--users",
                    "passwords": "--passwords"
                },
                
                "usage_examples": [
                    {
                        "description": "Basic SQL injection test",
                        "input": {
                            "target": "192.168.1.10",
                            "extra_args": "-u http://192.168.1.10/page.php?id=1 --batch"
                        },
                        "command": "sqlmap -u 'http://192.168.1.10/page.php?id=1' --batch"
                    },
                    {
                        "description": "Database enumeration with level 2",
                        "input": {
                            "target": "192.168.1.10",
                            "extra_args": "-u http://192.168.1.10/page.php?id=1 --batch --risk=2 --level=2 --dbs"
                        },
                        "command": "sqlmap -u 'http://192.168.1.10/page.php?id=1' --batch --risk=2 --level=2 --dbs"
                    },
                    {
                        "description": "Table enumeration in specific database",
                        "input": {
                            "target": "192.168.1.10",
                            "extra_args": "-u http://192.168.1.10/page.php?id=1 --batch -D testdb --tables"
                        },
                        "command": "sqlmap -u 'http://192.168.1.10/page.php?id=1' --batch -D testdb --tables"
                    },
                    {
                        "description": "Dump specific table",
                        "input": {
                            "target": "192.168.1.10",
                            "extra_args": "-u http://192.168.1.10/page.php?id=1 --batch -D testdb -T users --dump"
                        },
                        "command": "sqlmap -u 'http://192.168.1.10/page.php?id=1' --batch -D testdb -T users --dump"
                    },
                    {
                        "description": "POST request with data",
                        "input": {
                            "target": "192.168.1.10",
                            "extra_args": "-u http://192.168.1.10/login.php --batch --data=username=admin&password=test"
                        },
                        "command": "sqlmap -u 'http://192.168.1.10/login.php' --batch --data='username=admin&password=test'"
                    }
                ],
                
                "common_dbms": [
                    "MySQL",
                    "PostgreSQL",
                    "Microsoft SQL Server",
                    "Oracle",
                    "SQLite"
                ],
                
                "warnings": [
                    "AUTHORIZED USE ONLY - Only use on systems you own or have permission to test",
                    "SQL injection testing can modify database contents",
                    "May trigger security alerts and IDS/IPS systems",
                    "Can cause database performance degradation",
                    "May have legal consequences if misused",
                    "Always use --batch mode for automated testing",
                    "Keep risk and level at safe values (1-2)"
                ]
            }
        }
        
        base_info.update(sqlmap_info)
        return base_info
    
    def validate_configuration(self) -> Dict[str, Any]:
        """
        Validate current tool configuration.
        
        Checks:
        - Command availability
        - Configuration settings
        - Circuit breaker state
        
        Returns:
            Dictionary with validation results
        """
        issues = []
        warnings = []
        
        # Check if sqlmap is available
        if not self._resolve_command():
            issues.append("sqlmap command not found in PATH")
        
        # Check circuit breaker state
        if self._circuit_breaker:
            try:
                from mcp_server.circuit_breaker import CircuitBreakerState
                if self._circuit_breaker.state == CircuitBreakerState.OPEN:
                    warnings.append("Circuit breaker is currently OPEN")
            except Exception:
                pass
        
        # Check timeout
        if self.default_timeout_sec < 60:
            warnings.append(f"Very low timeout: {self.default_timeout_sec}s")
        
        # Security warning
        warnings.append("ATTACK TOOL - Use only on authorized systems")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "configuration": {
                "command_available": self._resolve_command() is not None,
                "timeout": self.default_timeout_sec,
                "concurrency": self.concurrency,
                "max_risk_level": self.MAX_RISK_LEVEL,
                "max_test_level": self.MAX_TEST_LEVEL,
                "max_threads": self.MAX_THREADS,
            }
        }
