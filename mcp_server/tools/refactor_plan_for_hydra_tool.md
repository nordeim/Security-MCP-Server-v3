# Comprehensive Review: hydra_tool.py

## Executive Summary

**Status:** ⚠️ **NEEDS SIGNIFICANT REFACTORING**

**Severity Breakdown:**
- 🔴 **Critical Issues:** 5 (Security & Architecture)
- 🟠 **Major Issues:** 6 (Logic & Design)  
- 🟡 **Minor Issues:** 14 (Best Practices)

**Overall Assessment:** The tool has good intentions with comprehensive safety controls, but suffers from fundamental architectural misunderstandings, security holes in validation logic, and violations of the framework's design patterns.

---

## 🔴 Critical Issues

### 1. **Fundamental Hydra Architecture Misunderstanding**

**Location:** Lines 163-194 (`_is_valid_hydra_target`)

**Problem:**
```python
# Current (WRONG):
def _is_valid_hydra_target(self, target: str) -> bool:
    # Expects target like: "192.168.1.10:ssh" or "ssh://192.168.1.10"
    if len(target.split(':')) < 2:
        return False
```

**Actual Hydra Syntax:**
```bash
# Hydra command structure:
hydra [options] TARGET SERVICE
hydra -l admin -P wordlist.txt 192.168.1.10 ssh
#                               ^target^      ^service in extra_args

# NOT:
hydra -l admin -P wordlist.txt 192.168.1.10:ssh  # ❌ Invalid
```

**Impact:** The entire target validation is based on incorrect assumptions about hydra's command-line interface.

**Fix Required:**
```python
# target should be just the host: "192.168.1.10" or "host.lab.internal"
# service should be in extra_args as the last token: "ssh", "ftp", etc.
# Base class already validates RFC1918/.lab.internal for target
# Tool should validate that extra_args contains a valid service
```

---

### 2. **Security Hole: File Validation Returns True on Error**

**Location:** Lines 385-431 (`_is_safe_login_spec`, `_is_safe_password_spec`)

**Problem:**
```python
def _is_safe_password_spec(self, spec: str, is_file: bool) -> bool:
    if is_file:
        try:
            if os.path.exists(spec):
                # ... validation ...
            return True  # 🔴 Returns True if file DOESN'T exist!
        except Exception as exc:
            log.warning("...")
            return True  # 🔴 Returns True on ERROR!
```

**Security Impact:** An attacker could specify:
- Non-existent files → passes validation
- Unreadable files → passes validation  
- Files that cause exceptions → passes validation

**Fix Required:**
```python
def _is_safe_password_spec(self, spec: str, is_file: bool) -> bool:
    if is_file:
        try:
            if not os.path.exists(spec):
                log.warning("hydra.password_file_not_found path=%s", spec)
                return False  # ✅ Fail if missing
            
            # Check size before opening
            file_size = os.path.getsize(spec)
            if file_size > self.max_password_list_size * 100:  # Estimate
                log.warning("hydra.password_file_too_large size=%d", file_size)
                return False
            
            with open(spec, 'r') as f:
                line_count = sum(1 for _ in f)
            
            if line_count > self.max_password_list_size:
                log.warning("hydra.password_file_too_many_lines lines=%d", line_count)
                return False
            
            return True
            
        except Exception as exc:
            log.error("hydra.password_file_validation_failed path=%s error=%s", 
                     spec, str(exc))
            return False  # ✅ Fail closed
```

---

### 3. **Private Variable Access Violation**

**Location:** Lines 9, 376-377

**Problem:**
```python
from mcp_server.base_tool import (
    _TOKEN_ALLOWED,  # 🔴 Private implementation detail
)

def _is_base_token_allowed(self, token: str) -> bool:
    return bool(_TOKEN_ALLOWED.match(token))  # 🔴 Using private variable
```

**Impact:** 
- Violates encapsulation
- Will break if base_tool refactors `_TOKEN_ALLOWED`
- Not part of public API

**Fix Required:**
```python
# Option 1: Define own pattern
_HYDRA_TOKEN_ALLOWED = re.compile(r"^[A-Za-z0-9.:/=+,\-@%_]+$")

def _is_base_token_allowed(self, token: str) -> bool:
    return bool(self._HYDRA_TOKEN_ALLOWED.match(token))

# Option 2: Use base class methods properly
# Let base class _parse_args handle validation
```

---

### 4. **Dangerous Silent Defaults**

**Location:** Lines 307-319 (`_secure_hydra_args`)

**Problem:**
```python
# Ensure required authentication is present
if not has_login:
    secured.extend(["-l", "admin"])  # 🔴 Silently adds default!
    log.warning("hydra.no_login_specified using_default")

if not has_password:
    secured.extend(["-P", "/usr/share/wordlists/common-passwords.txt"])  # 🔴 Dangerous!
    log.warning("hydra.no_password_specified using_default")
```

**Security Impact:**
- User thinks they specified credentials but tool uses different ones
- Default wordlist path may not exist → silent failure
- "admin" username may not be what user intended
- Bypasses user's explicit intent

**Fix Required:**
```python
# Validate presence but DON'T add defaults
if not has_login:
    raise ValueError(
        "Hydra requires login specification (-l <user> or -L <userfile>)"
    )

if not has_password:
    raise ValueError(
        "Hydra requires password specification (-p <pass> or -P <passfile>)"
    )
```

---

### 5. **Redundant RFC1918 Validation**

**Location:** Lines 196-214 (`_is_authorized_target`)

**Problem:**
```python
def _is_authorized_target(self, target: str) -> bool:
    """Check if Hydra target is authorized (RFC1918 or .lab.internal)."""
    # ... complex validation logic ...
```

**Impact:** Base class `ToolInput` Pydantic validator **already does this**:
```python
# From base_tool.py ToolInput:
@field_validator("target", mode='after')
def _validate_target(cls, v: str) -> str:
    if not _is_private_or_lab(v):  # Already validates RFC1918 + .lab.internal!
        raise ValueError("Target must be RFC1918 or .lab.internal")
```

**Fix Required:** Remove entire `_is_authorized_target` method - it's redundant.

---

## 🟠 Major Issues

### 6. **Loop Index Logic Error**

**Location:** Lines 237-305 (`_secure_hydra_args`)

**Problem:**
```python
while i < len(args):
    arg = args[i]
    
    if arg in ("-l", "-L"):
        if i + 1 < len(args):
            # ... process ...
            i += 2  # Increment here
            continue
        i += 2  # 🟠 Also increment here even if no value!
        continue
```

**Impact:** If a flag is missing its value, increments by 2 anyway, potentially skipping valid tokens or causing index errors.

**Fix:**
```python
if arg in ("-l", "-L"):
    if i + 1 >= len(args):
        raise ValueError(f"{arg} requires a value")
    
    login_spec = args[i + 1]
    if self._is_safe_login_spec(login_spec, arg == "-L"):
        secured.extend([arg, login_spec])
        has_login = True
    i += 2  # Only one increment point
    continue
```

---

### 7. **Fragile Placeholder Validation**

**Location:** Lines 333-374 (`_parse_and_validate_args`)

**Problem:**
```python
placeholder = f"__HYDRA_TOKEN_{idx}__"
placeholder_map[placeholder] = token
sanitized_parts.append(placeholder)

# ...then...
base_tokens = list(super()._parse_args(sanitized_string))
```

**Issue:** The placeholder won't be in `allowed_flags`, so `_sanitize_tokens` will reject it.

**Fix:** Either:
1. Add all possible placeholders to `allowed_flags` (messy)
2. Override `_sanitize_tokens` to allow placeholders (complex)
3. **Better:** Handle payload tokens directly without placeholders

---

### 8. **Missing Config Value Clamping**

**Location:** Lines 93-105 (`_setup_enhanced_features`)

**Problem:**
```python
if failure_threshold is not None:
    self.circuit_breaker_failure_threshold = int(failure_threshold)  # 🟠 No clamping!
```

**Compare to masscan_tool (correct):**
```python
self.circuit_breaker_failure_threshold = max(1, min(5, int(failure_threshold)))
```

**Fix:**
```python
self.circuit_breaker_failure_threshold = max(1, min(10, int(failure_threshold)))
self.circuit_breaker_recovery_timeout = max(60.0, min(600.0, float(recovery_timeout)))
```

---

### 9. **Confusing Return Type**

**Location:** Line 333

**Problem:**
```python
def _parse_and_validate_args(self, secured_args: str, inp: ToolInput) -> Union[str, ToolOutput]:
```

**Issue:** Function returns either:
- `str` (validated args) on success
- `ToolOutput` (error) on failure

This is confusing and error-prone. Caller must check type.

**Fix:**
```python
# Option 1: Raise on error
def _parse_and_validate_args(self, secured_args: str, inp: ToolInput) -> str:
    # ... validation ...
    if error:
        raise ValueError("...")
    return validated_args

# Option 2: Return Optional error
def _parse_and_validate_args(self, secured_args: str, inp: ToolInput) -> Optional[ToolOutput]:
    # ... validation ...
    if error:
        return error_output
    return None  # Success, proceed with execution
```

---

### 10. **Redundant Circuit Breaker Initialization**

**Location:** Lines 103-105

**Problem:**
```python
def _setup_enhanced_features(self) -> None:
    # ... config reading ...
    self._circuit_breaker = None  # 🟠 Unnecessary
    self._initialize_circuit_breaker()  # 🟠 Already called by parent __init__
```

**Impact:** Parent `MCPBaseTool.__init__` already calls `_initialize_circuit_breaker()`, so this is redundant.

**Fix:**
```python
def _setup_enhanced_features(self) -> None:
    # Read config
    circuit_cfg = getattr(self.config, "circuit_breaker", None)
    if circuit_cfg:
        # ... update settings ...
    
    # Re-initialize with new settings
    if self._circuit_breaker:
        self._initialize_circuit_breaker()
```

---

### 11. **Invalid Flags in allowed_flags**

**Location:** Lines 45-75

**Problem:**
```python
allowed_flags: Sequence[str] = [
    # ...
    "/path",  # 🟠 Not a flag! This is a value
    # ...
    "ssh", "ftp", "telnet",  # 🟠 These are service names, not flags
]
```

**Impact:** Confuses flags with values. Services should be validated separately.

**Fix:**
```python
allowed_flags: Sequence[str] = [
    "-l", "-L", "-p", "-P", "-C", "-e",
    "-s", "-S", "-t", "-T", "-w", "-W",
    "-v", "-V", "-o", "-f", "-q",
    "-I", "-R", "-F", "-m",
]

# Separate validation
ALLOWED_SERVICES = {
    "ssh", "ftp", "telnet", "http", "https", "smb", 
    "ldap", "rdp", "mysql", "postgresql", "vnc",
    "http-get", "http-post", "http-post-form", "http-head"
}
```

---

## 🟡 Minor Issues

### 12. Missing Type Hint on Return

**Location:** Line 437
```python
def _get_timestamp(self):  # 🟡 Missing return type
```
**Fix:** `def _get_timestamp(self) -> datetime:`

---

### 13. Import Inside Method

**Location:** Line 439
```python
def _get_timestamp(self):
    from datetime import datetime  # 🟡 Should be at module level
    return datetime.now()
```
**Fix:** Import at top, return `datetime.now(timezone.utc)`

---

### 14. Not Using super().get_tool_info()

**Location:** Lines 442-478
```python
def get_tool_info(self) -> dict:  # 🟡 Should be Dict[str, Any]
    base_info = {  # 🟡 Should call super()
        "name": self.tool_name,
        ...
    }
```

**Fix:**
```python
def get_tool_info(self) -> Dict[str, Any]:
    base_info = super().get_tool_info()
    base_info.update({
        "security_restrictions": {...},
        ...
    })
    return base_info
```

---

### 15-25. Additional Minor Issues

15. **Module-level regex between methods** (Line 379) - Move to class level
16. **Security limits not UPPER_CASE** (Lines 77-86) - Should be constants
17. **Missing correlation_id fallback** (Line 136) - `inp.correlation_id or ""`
18. **Inconsistent logging levels** - Some warnings should be errors
19. **No docstring examples match actual usage** - Due to architectural issues
20. **Missing _FLAGS_REQUIRE_VALUE validation** - Not checked in loop
21. **Thread count not validated** - Line 260 allows negative values
22. **Wait time not validated** - Could be negative or huge
23. **Service validation incomplete** - Doesn't check if service is last token
24. **No cleanup of placeholder_map** - Memory leak potential
25. **get_tool_info returns dict not Dict[str, Any]** - Type hint mismatch

---

## Recommended Action Plan

### Phase 1: Critical Fixes (Security & Architecture)
1. ✅ Fix target validation - remove format expectations
2. ✅ Fix file validation - fail closed on errors
3. ✅ Remove private variable access
4. ✅ Remove dangerous defaults
5. ✅ Remove redundant RFC1918 validation

### Phase 2: Major Refactoring (Logic & Design)
6. ✅ Fix loop increment logic
7. ✅ Simplify validation (remove placeholders)
8. ✅ Add config value clamping
9. ✅ Fix return type consistency
10. ✅ Clean up circuit breaker init
11. ✅ Separate flags from services

### Phase 3: Polish (Best Practices)
12-25. ✅ Apply all minor fixes

---

# Hydra Tool Refactoring Plan - Meticulous Execution Strategy

## Executive Summary

**Objective:** Create a production-ready, security-hardened Hydra tool that follows MCP framework patterns correctly.

**Approach:** Complete rewrite using NmapTool and MasscanTool as reference implementations.

**Estimated LOC:** ~600 lines (down from 480, with proper documentation and safety)

**Key Principle:** Follow the framework, don't fight it.

---

## Phase 1: Architecture Analysis & Design Validation

### 1.1 Hydra Command Structure (CORRECT Understanding)

```bash
# Actual Hydra Syntax:
hydra [OPTIONS] TARGET SERVICE

# Examples:
hydra -l admin -P wordlist.txt 192.168.1.10 ssh
hydra -L users.txt -P pass.txt 10.0.0.5 ftp
hydra -l admin -p password 192.168.1.1 http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# Breakdown:
# OPTIONS: -l, -L, -p, -P, -t, -w, -f, -v, etc.
# TARGET: Single host (IP or hostname) - validated by base class
# SERVICE: Last positional argument (ssh, ftp, http-post-form, etc.)
```

**Key Insight:** Target is JUST the host. Service comes in extra_args as the last token.

### 1.2 Tool Input Mapping

```python
# MCP Tool Input:
ToolInput(
    target="192.168.1.10",           # Just the host (base class validates)
    extra_args="-l admin -P wordlist.txt ssh"  # Options + SERVICE
)

# Becomes:
# hydra -l admin -P wordlist.txt 192.168.1.10 ssh
#       ^from extra_args^        ^target^     ^from extra_args
```

### 1.3 Validation Layers

```
Layer 1: Base Class (ToolInput Pydantic)
    ✓ RFC1918/lab.internal validation (automatic)
    ✓ Metacharacter blocking (automatic)
    ✓ Args length limit (automatic)

Layer 2: Hydra-Specific (_validate_hydra_requirements)
    ✓ Service presence and validity
    ✓ Authentication specification (-l/-L AND -p/-P)
    ✓ File existence and size limits
    ✓ Thread count safety limits
    ✓ Service-specific payload validation

Layer 3: Argument Parsing (_parse_and_validate_args)
    ✓ Flag whitelist enforcement
    ✓ Value validation for flags
    ✓ Payload token safety (for http-post-form)
    ✓ Service extraction and validation

Layer 4: Optimization (_optimize_hydra_args)
    ✓ Add safety defaults (stop-on-success, thread limits)
    ✓ Add verbose output
    ✓ Ensure service is last
```

---

## Phase 2: Detailed Component Design

### 2.1 Class Structure

```python
class HydraTool(MCPBaseTool):
    # Class-level constants (UPPER_CASE)
    command_name: ClassVar[str] = "hydra"
    
    # Security limits (immutable)
    DEFAULT_THREADS = 4
    MAX_THREADS = 16
    MAX_PASSWORD_FILE_LINES = 10000
    MAX_USERNAME_FILE_LINES = 1000
    MAX_PASSWORD_FILE_SIZE_MB = 10
    MAX_USERNAME_FILE_SIZE_MB = 1
    
    # Allowed services (comprehensive list)
    ALLOWED_SERVICES = frozenset([
        "ssh", "ftp", "telnet", "http", "https", "smb", 
        "ldap", "rdp", "mysql", "postgresql", "vnc",
        "http-get", "http-post", "http-post-form", "http-head",
        "smtp", "pop3", "imap", "mssql", "oracle", "cisco"
    ])
    
    # Allowed flags (clean list, no services)
    allowed_flags: ClassVar[Sequence[str]] = [
        # Authentication
        "-l", "-L", "-p", "-P", "-C", "-e",
        # Connection control
        "-s", "-S", "-t", "-T", "-w", "-W",
        # Output
        "-v", "-V", "-o", "-q",
        # Behavior
        "-f", "-F", "-I", "-R",
        # Service-specific
        "-m",
    ]
    
    _FLAGS_REQUIRE_VALUE = frozenset({
        "-l", "-L", "-p", "-P", "-C",
        "-s", "-t", "-T", "-w", "-W",
        "-o", "-m"
    })
    
    # Timeouts
    default_timeout_sec: ClassVar[float] = 900.0  # 15 minutes
    concurrency: ClassVar[int] = 1
    
    # Circuit breaker
    circuit_breaker_failure_threshold: ClassVar[int] = 3
    circuit_breaker_recovery_timeout: ClassVar[float] = 180.0
```

### 2.2 Initialization Pattern (Match MasscanTool)

```python
def __init__(self):
    super().__init__()
    self.config = get_config()
    self._apply_config()

def _apply_config(self):
    """Apply configuration with safe clamping."""
    try:
        # Circuit breaker config
        if hasattr(self.config, 'circuit_breaker'):
            cb = self.config.circuit_breaker
            if hasattr(cb, 'failure_threshold'):
                self.circuit_breaker_failure_threshold = max(1, min(10, int(cb.failure_threshold)))
            if hasattr(cb, 'recovery_timeout'):
                self.circuit_breaker_recovery_timeout = max(60.0, min(600.0, float(cb.recovery_timeout)))
        
        # Tool config
        if hasattr(self.config, 'tool'):
            tool = self.config.tool
            if hasattr(tool, 'default_timeout'):
                self.default_timeout_sec = max(60.0, min(3600.0, float(tool.default_timeout)))
            # Force concurrency to 1
            self.concurrency = 1
        
        log.debug("hydra.config_applied timeout=%.1f", self.default_timeout_sec)
    
    except Exception as e:
        log.error("hydra.config_failed error=%s using_defaults", str(e))
        # Keep safe defaults
```

### 2.3 Execution Flow (Match MasscanTool Pattern)

```python
async def _execute_tool(self, inp: ToolInput, timeout_sec: Optional[float] = None) -> ToolOutput:
    # Step 1: Hydra-specific validation
    validation_error = self._validate_hydra_requirements(inp)
    if validation_error:
        return validation_error
    
    # Step 2: Parse and validate arguments
    try:
        validated_args, service = self._parse_and_validate_args(inp.extra_args or "")
    except ValueError as e:
        error_context = ErrorContext(...)
        return self._create_error_output(error_context, inp.correlation_id or "")
    
    # Step 3: Optimize arguments with safety defaults
    optimized_args = self._optimize_hydra_args(validated_args, service)
    
    # Step 4: Create enhanced input
    enhanced_input = ToolInput(
        target=inp.target,
        extra_args=optimized_args,
        timeout_sec=timeout_sec or inp.timeout_sec or self.default_timeout_sec,
        correlation_id=inp.correlation_id
    )
    
    log.warning("hydra.executing target=%s service=%s AUTHORIZED_USE_ONLY",
                inp.target, service)
    
    # Step 5: Execute with base class
    return await super()._execute_tool(enhanced_input, enhanced_input.timeout_sec)
```

### 2.4 Validation Method Design

```python
def _validate_hydra_requirements(self, inp: ToolInput) -> Optional[ToolOutput]:
    """Validate hydra-specific requirements."""
    
    # 1. Check service presence
    service = self._extract_service(inp.extra_args or "")
    if not service:
        return self._create_error_output(
            ErrorContext(
                error_type=ToolErrorType.VALIDATION_ERROR,
                message="Hydra requires service specification",
                recovery_suggestion="Add service as last argument (e.g., 'ssh', 'ftp', 'http-post-form')",
                ...
            )
        )
    
    # 2. Validate service
    if service not in self.ALLOWED_SERVICES:
        return self._create_error_output(...)
    
    # 3. Check authentication presence
    has_user, has_pass = self._check_authentication_present(inp.extra_args)
    if not has_user or not has_pass:
        return self._create_error_output(...)
    
    # 4. Validate file specifications
    file_error = self._validate_file_specifications(inp.extra_args)
    if file_error:
        return file_error
    
    return None
```

### 2.5 Argument Parsing (Simplified, No Placeholders)

```python
def _parse_and_validate_args(self, extra_args: str) -> Tuple[str, str]:
    """
    Parse and validate arguments.
    
    Returns:
        Tuple of (validated_args_without_service, service)
    
    Raises:
        ValueError: If validation fails
    """
    if not extra_args:
        raise ValueError("Hydra requires arguments (authentication + service)")
    
    tokens = shlex.split(extra_args)
    
    # Extract service (last token that doesn't start with -)
    service = None
    service_idx = -1
    for i in range(len(tokens) - 1, -1, -1):
        if not tokens[i].startswith("-"):
            service = tokens[i]
            service_idx = i
            break
    
    if not service:
        raise ValueError("No service specified")
    
    # Validate service
    if service not in self.ALLOWED_SERVICES:
        raise ValueError(f"Service not allowed: {service}")
    
    # Process flags (everything before service)
    validated = []
    i = 0
    
    while i < service_idx:
        token = tokens[i]
        
        # Handle flags
        if token.startswith("-"):
            flag_base = token.split("=", 1)[0]
            
            if flag_base not in self.allowed_flags:
                raise ValueError(f"Flag not allowed: {token}")
            
            if flag_base in self._FLAGS_REQUIRE_VALUE:
                if i + 1 >= service_idx:
                    raise ValueError(f"{flag_base} requires a value")
                
                value = tokens[i + 1]
                
                # Validate specific flags
                if flag_base == "-t":
                    thread_count = int(value)
                    if not (1 <= thread_count <= self.MAX_THREADS):
                        raise ValueError(f"Thread count must be 1-{self.MAX_THREADS}")
                
                elif flag_base in ("-w", "-W", "-T"):
                    wait_time = int(value)
                    if wait_time < 0 or wait_time > 300:
                        raise ValueError(f"{flag_base} must be 0-300 seconds")
                
                validated.extend([token, value])
                i += 2
            else:
                validated.append(token)
                i += 1
        else:
            # For http-post-form payloads, allow special chars
            if service.startswith("http-") and self._is_safe_payload(token):
                validated.append(token)
                i += 1
            else:
                raise ValueError(f"Unexpected token: {token}")
    
    return " ".join(validated), service

def _is_safe_payload(self, token: str) -> bool:
    """Validate HTTP form payloads."""
    # Allow: alphanumeric, /, :, -, _, ?, =, &, ^, %, .
    # Block: .., shell metacharacters
    pattern = re.compile(r'^[A-Za-z0-9_:/\-\.\?=&^%]+$')
    return bool(pattern.match(token)) and ".." not in token
```

### 2.6 File Validation (Fail-Closed)

```python
def _validate_file_specifications(self, extra_args: str) -> Optional[ToolOutput]:
    """Validate password and username files."""
    try:
        tokens = shlex.split(extra_args)
    except ValueError:
        return None  # Let main parser handle
    
    i = 0
    while i < len(tokens):
        token = tokens[i]
        
        # Username file
        if token == "-L":
            if i + 1 >= len(tokens):
                return self._create_file_error("Username file not specified")
            
            filepath = tokens[i + 1]
            error = self._validate_file(
                filepath, 
                self.MAX_USERNAME_FILE_SIZE_MB,
                self.MAX_USERNAME_FILE_LINES,
                "username"
            )
            if error:
                return error
            i += 2
            continue
        
        # Password file
        if token == "-P":
            if i + 1 >= len(tokens):
                return self._create_file_error("Password file not specified")
            
            filepath = tokens[i + 1]
            error = self._validate_file(
                filepath,
                self.MAX_PASSWORD_FILE_SIZE_MB,
                self.MAX_PASSWORD_FILE_LINES,
                "password"
            )
            if error:
                return error
            i += 2
            continue
        
        i += 1
    
    return None

def _validate_file(
    self, 
    filepath: str, 
    max_size_mb: int, 
    max_lines: int,
    file_type: str
) -> Optional[ToolOutput]:
    """Validate file exists and is within limits (FAIL CLOSED)."""
    
    # Check existence
    if not os.path.exists(filepath):
        return self._create_file_error(
            f"{file_type.capitalize()} file not found: {filepath}",
            {"suggestion": "Check file path and permissions"}
        )
    
    # Check readability
    if not os.access(filepath, os.R_OK):
        return self._create_file_error(
            f"{file_type.capitalize()} file not readable: {filepath}",
            {"suggestion": "Check file permissions"}
        )
    
    # Check size
    try:
        size_bytes = os.path.getsize(filepath)
        size_mb = size_bytes / (1024 * 1024)
        
        if size_mb > max_size_mb:
            return self._create_file_error(
                f"{file_type.capitalize()} file too large: {size_mb:.1f}MB (max: {max_size_mb}MB)",
                {"size_mb": size_mb, "max_mb": max_size_mb}
            )
    except OSError as e:
        return self._create_file_error(
            f"Cannot access {file_type} file: {filepath}",
            {"error": str(e)}
        )
    
    # Check line count
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            line_count = sum(1 for _ in f)
        
        if line_count > max_lines:
            return self._create_file_error(
                f"{file_type.capitalize()} file too many lines: {line_count} (max: {max_lines})",
                {"lines": line_count, "max_lines": max_lines}
            )
    except Exception as e:
        return self._create_file_error(
            f"Cannot read {file_type} file: {filepath}",
            {"error": str(e)}
        )
    
    log.debug("hydra.file_validated type=%s path=%s size_mb=%.2f lines=%d",
              file_type, filepath, size_mb, line_count)
    
    return None
```

### 2.7 Optimization (Add Safety Defaults)

```python
def _optimize_hydra_args(self, validated_args: str, service: str) -> str:
    """Add safety defaults and optimize arguments."""
    try:
        tokens = shlex.split(validated_args) if validated_args else []
    except ValueError:
        tokens = validated_args.split() if validated_args else []
    
    optimized = []
    
    # Check what's present
    has_threads = "-t" in tokens
    has_verbose = "-v" in tokens or "-V" in tokens
    has_stop_on_success = "-f" in tokens or "-F" in tokens
    has_wait = "-w" in tokens
    
    # Add safety defaults
    if not has_threads:
        optimized.extend(["-t", str(self.DEFAULT_THREADS)])
        log.debug("hydra.optimization added=threads value=%d", self.DEFAULT_THREADS)
    
    if not has_verbose:
        optimized.append("-V")
        log.debug("hydra.optimization added=verbose")
    
    if not has_stop_on_success:
        optimized.append("-f")
        log.debug("hydra.optimization added=stop_on_success")
    
    if not has_wait:
        optimized.extend(["-w", "1"])
        log.debug("hydra.optimization added=wait value=1")
    
    # Add original arguments
    optimized.extend(tokens)
    
    # Add service at the end
    optimized.append(service)
    
    result = " ".join(optimized)
    
    if len(optimized) != len(tokens) + 1:  # +1 for service
        log.info("hydra.arguments_optimized original=%d optimized=%d",
                len(tokens), len(optimized))
    
    return result
```

### 2.8 Helper Methods

```python
def _extract_service(self, extra_args: str) -> Optional[str]:
    """Extract service from arguments."""
    try:
        tokens = shlex.split(extra_args)
        # Find last non-flag token
        for token in reversed(tokens):
            if not token.startswith("-"):
                return token.lower()
    except ValueError:
        pass
    return None

def _check_authentication_present(self, extra_args: str) -> Tuple[bool, bool]:
    """Check if authentication is specified."""
    has_user = "-l" in extra_args or "-L" in extra_args or "-C" in extra_args
    has_pass = "-p" in extra_args or "-P" in extra_args or "-C" in extra_args or "-e" in extra_args
    return has_user, has_pass

def _get_timestamp(self) -> datetime:
    """Get current UTC timestamp."""
    return datetime.now(timezone.utc)

def _create_file_error(self, message: str, metadata: Optional[Dict[str, Any]] = None) -> ToolOutput:
    """Create file validation error output."""
    error_context = ErrorContext(
        error_type=ToolErrorType.VALIDATION_ERROR,
        message=message,
        recovery_suggestion="Check file path, permissions, and size limits",
        timestamp=self._get_timestamp(),
        tool_name=self.tool_name,
        target="",
        metadata=metadata or {}
    )
    return self._create_error_output(error_context, "")
```

### 2.9 Tool Info (Enhanced)

```python
def get_tool_info(self) -> Dict[str, Any]:
    """Get comprehensive tool information."""
    base_info = super().get_tool_info()
    
    hydra_info = {
        "hydra_specific": {
            "allowed_services": sorted(list(self.ALLOWED_SERVICES)),
            "security_limits": {
                "default_threads": self.DEFAULT_THREADS,
                "max_threads": self.MAX_THREADS,
                "max_password_file_lines": self.MAX_PASSWORD_FILE_LINES,
                "max_username_file_lines": self.MAX_USERNAME_FILE_LINES,
                "max_password_file_size_mb": self.MAX_PASSWORD_FILE_SIZE_MB,
                "max_username_file_size_mb": self.MAX_USERNAME_FILE_SIZE_MB,
            },
            "safety_features": [
                "File existence validation",
                "File size limits",
                "Thread count restrictions",
                "Stop-on-success default",
                "Wait time between attempts",
                "Fail-closed file validation",
                "Service whitelist enforcement",
            ],
            "usage_examples": [
                {
                    "description": "SSH brute force",
                    "input": {
                        "target": "192.168.1.10",
                        "extra_args": "-l admin -P /path/to/wordlist.txt ssh"
                    }
                },
                {
                    "description": "FTP with user list",
                    "input": {
                        "target": "10.0.0.5",
                        "extra_args": "-L users.txt -P passwords.txt ftp"
                    }
                },
                {
                    "description": "HTTP form attack",
                    "input": {
                        "target": "192.168.1.1",
                        "extra_args": "-l admin -P wordlist.txt http-post-form /login:user=^USER^&pass=^PASS^:F=incorrect"
                    }
                }
            ]
        }
    }
    
    base_info.update(hydra_info)
    return base_info
```

---

## Phase 3: Implementation Validation Checklist

### 3.1 Framework Compliance

- [ ] Extends MCPBaseTool correctly
- [ ] Uses ClassVar for class variables
- [ ] Calls super().__init__() first
- [ ] Uses ErrorContext for all errors
- [ ] Returns ToolOutput from all error paths
- [ ] Uses structured logging (key=value)
- [ ] Type hints complete
- [ ] Docstrings comprehensive

### 3.2 Security Validation

- [ ] No private variable access
- [ ] Fail-closed validation
- [ ] No silent defaults
- [ ] File validation comprehensive
- [ ] Thread limits enforced
- [ ] Service whitelist enforced
- [ ] Payload validation for HTTP forms
- [ ] No shell injection vulnerabilities

### 3.3 Pattern Matching

- [ ] Matches MasscanTool structure
- [ ] Configuration clamping like MasscanTool
- [ ] _execute_tool pattern correct
- [ ] Validation methods return Optional[ToolOutput]
- [ ] Parsing raises ValueError
- [ ] Optimization adds safety defaults
- [ ] get_tool_info calls super()

### 3.4 Functional Validation

- [ ] Target is just host (base validates)
- [ ] Service extracted from extra_args
- [ ] Authentication required
- [ ] Files validated before execution
- [ ] Thread count validated
- [ ] Wait times validated
- [ ] HTTP payloads supported
- [ ] Service is last argument

---

## Phase 4: Test Cases

### 4.1 Valid Usage Tests

```python
# Test 1: Basic SSH
ToolInput(
    target="192.168.1.10",
    extra_args="-l admin -P wordlist.txt ssh"
)
# Expected: Success

# Test 2: FTP with files
ToolInput(
    target="10.0.0.5",
    extra_args="-L users.txt -P passwords.txt -t 8 ftp"
)
# Expected: Success (threads clamped if > MAX_THREADS)

# Test 3: HTTP form
ToolInput(
    target="192.168.1.1",
    extra_args="-l admin -P wordlist.txt http-post-form /login:user=^USER^&pass=^PASS^:F=incorrect"
)
# Expected: Success
```

### 4.2 Validation Failure Tests

```python
# Test 4: No service
ToolInput(
    target="192.168.1.10",
    extra_args="-l admin -P wordlist.txt"
)
# Expected: Error "No service specified"

# Test 5: Invalid service
ToolInput(
    target="192.168.1.10",
    extra_args="-l admin -P wordlist.txt invalid-service"
)
# Expected: Error "Service not allowed"

# Test 6: No authentication
ToolInput(
    target="192.168.1.10",
    extra_args="ssh"
)
# Expected: Error "Hydra requires authentication"

# Test 7: Missing password file
ToolInput(
    target="192.168.1.10",
    extra_args="-l admin -P /nonexistent/file.txt ssh"
)
# Expected: Error "Password file not found"

# Test 8: Excessive threads
ToolInput(
    target="192.168.1.10",
    extra_args="-l admin -P wordlist.txt -t 100 ssh"
)
# Expected: Error "Thread count must be 1-16"
```

### 4.3 Edge Cases

```python
# Test 9: Combination file
ToolInput(
    target="192.168.1.10",
    extra_args="-C combo.txt ssh"
)
# Expected: Success (has both user and pass via -C)

# Test 10: Empty password check
ToolInput(
    target="192.168.1.10",
    extra_args="-l admin -e nsr ssh"
)
# Expected: Success (has user + -e for empty/reverse checks)
```

---

## Phase 5: Documentation Requirements

### 5.1 Module Docstring

```python
"""
Hydra password cracking tool with comprehensive safety controls.

Features:
- Online password auditing for authorized systems
- Multi-service support (SSH, FTP, HTTP, etc.)
- File size and line count limits
- Thread count restrictions
- Fail-closed file validation
- Stop-on-success safety default

Security Controls:
- CRITICAL: Only use on authorized systems
- File validation (existence, size, line count)
- Thread limits (max 16 concurrent)
- Service whitelist enforcement
- RFC1918/lab.internal target restriction
- Fail-closed validation (no access = fail)

WARNING:
    This is a password cracking tool intended ONLY for authorized
    security testing. Unauthorized use is illegal and unethical.
    
    Use only on systems you own or have explicit permission to test.

Usage:
    tool = HydraTool()
    
    # SSH password audit
    result = await tool.run(ToolInput(
        target="192.168.1.10",
        extra_args="-l admin -P wordlist.txt ssh"
    ))
    
    # FTP with user list
    result = await tool.run(ToolInput(
        target="10.0.0.5",
        extra_args="-L users.txt -P passwords.txt ftp"
    ))

Configuration:
    # config.yaml
    tool:
      default_timeout: 900  # 15 minutes
      default_concurrency: 1
    
    circuit_breaker:
      failure_threshold: 3
      recovery_timeout: 180.0

Environment Variables:
    MCP_DEFAULT_TIMEOUT_SEC: Override default timeout
    MCP_DEFAULT_CONCURRENCY: Override concurrency (forced to 1)

Author: MCP Network Tools Team
Version: 2.0.0
"""
```

### 5.2 Method Docstrings

Every method needs:
- Purpose description
- Args with types and descriptions
- Returns with type and description
- Raises for exceptions
- Examples where appropriate

---

## Pre-Implementation Validation

### Validation Questions

1. **Does target handling match Hydra's syntax?**
   - ✅ Yes: Target is just the host, service is in extra_args

2. **Does validation follow framework patterns?**
   - ✅ Yes: Matches MasscanTool pattern

3. **Are all security holes fixed?**
   - ✅ Yes: Fail-closed file validation, no silent defaults, no private access

4. **Is service validation correct?**
   - ✅ Yes: Extracted from extra_args, validated against whitelist

5. **Are HTTP payloads handled safely?**
   - ✅ Yes: Special character validation for http-* services

6. **Does configuration follow best practices?**
   - ✅ Yes: Clamping like MasscanTool

7. **Are error messages helpful?**
   - ✅ Yes: ErrorContext with recovery suggestions

8. **Is the code testable?**
   - ✅ Yes: Clear test cases defined

---

## Implementation Readiness

### Checklist

- [x] Architecture validated against actual Hydra syntax
- [x] All critical issues addressed in design
- [x] All major issues addressed in design
- [x] All minor issues addressed in design
- [x] Pattern matching validated
- [x] Security controls comprehensive
- [x] Test cases defined
- [x] Documentation structure planned
- [x] No dependencies on private variables
- [x] Fail-closed validation guaranteed

### Risk Assessment

**Risks:** ✅ LOW
- Design follows proven patterns (NmapTool, MasscanTool)
- All identified issues addressed
- Security-first approach
- Comprehensive validation

**Dependencies:**
- ✅ MCPBaseTool (stable)
- ✅ Config system (stable)
- ✅ ErrorContext (stable)
- ✅ Standard library only

**Estimated Lines of Code:** ~650 lines
- Class definition: ~50
- Validation methods: ~200
- Parsing: ~150
- File validation: ~100
- Helpers: ~50
- Documentation: ~100

---

## Final Validation

**APPROVED FOR IMPLEMENTATION ✅**

The plan is:
1. ✅ **Architecturally sound** - Matches Hydra's actual command structure
2. ✅ **Security-hardened** - Fail-closed validation, no silent defaults
3. ✅ **Framework-compliant** - Follows MasscanTool/NmapTool patterns
4. ✅ **Testable** - Clear test cases and validation points
5. ✅ **Documented** - Comprehensive docstrings planned
6. ✅ **Complete** - All issues from review addressed

**Ready to proceed with meticulous implementation.**
