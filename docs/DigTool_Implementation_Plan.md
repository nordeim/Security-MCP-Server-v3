# Plan: `DigTool` Implementation

## 1. Objective

To create a new, secure `DigTool` for performing DNS reconnaissance and add it to the `mcp_server/tools/` directory. This tool will be a safe wrapper around the standard `dig` command-line utility.

## 2. Rationale

The `dig` tool was chosen because it fills a critical gap in external DNS reconnaissance, complementing the existing internal-focused toolset. It presents a unique opportunity to implement custom target validation for public domain names, which differs from the server's default security policy, making it a valuable and instructive addition to the project.

## 3. Features Checklist

-   [ ] **Core Functionality:** Perform DNS lookups for specified domain names.
-   [ ] **Secure by Default:** Inherit all security features from `MCPBaseTool` (resource limits, concurrency control, circuit breaker).
-   [ ] **Custom Target Validation:** Implement logic to validate that the target is a well-formed domain name, overriding the default private IP check.
-   [ ] **Whitelisted Operations:**
    -   [ ] Allow a specific, safe set of DNS query types (e.g., `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`).
    -   [ ] Allow a specific, safe set of `dig` flags (e.g., `+short`, `+trace`).
-   [ ] **Structured Output:** Parse the raw text output from `dig` into a structured JSON format for easy consumption by an AI agent.
-   [ ] **Testing:** Include a comprehensive unit test suite to verify all security constraints and functionality.

## 4. Implementation Plan & Code Structure Checklist

### 4.1. File Creation
-   [ ] Create the main tool file: `mcp_server/tools/dig_tool.py`.
-   [ ] Create the corresponding test file: `tests/test_dig_tool.py`.

### 4.2. `DigTool` Class (`dig_tool.py`)
-   [ ] **Class Definition:**
    -   Define `class DigTool(MCPBaseTool):`.
-   [ ] **Core Attributes:**
    -   Set `command_name = "dig"`.
    -   Define `allowed_flags`: A tuple containing safe flags like `+short`, `+trace`, `+nocmd`, and the allowed query types (`A`, `MX`, etc.).
    -   Define `_FLAGS_REQUIRE_VALUE`: Specify any flags that require an argument.
-   [ ] **Custom Target Validation:**
    -   Override the `_execute_tool` method.
    -   Inside the override, implement a `_validate_domain` method that uses a regular expression to check if the `ToolInput.target` is a valid domain name.
    -   If validation fails, return a `ToolOutput` object with a clear validation error.
-   [ ] **Argument Validation:**
    -   In the `_execute_tool` override, parse `ToolInput.extra_args` to ensure that any specified query types are in the allowed list.
-   [ ] **Command Execution:**
    -   Call `super()._execute_tool()` with the validated input to execute the `dig` command.
-   [ ] **Output Parsing:**
    -   Implement a `_parse_dig_output` method.
    -   This method will use regular expressions to find and extract key information from the `dig` stdout, such as the `ANSWER SECTION`, record type, TTL, and value.
    -   Modify the `_execute_tool` method to call this parser on the result and embed the structured data into the `ToolOutput.metadata` field.
-   [ ] **Tool Information:**
    -   Implement the `get_tool_info` method to provide metadata about the tool's capabilities, allowed query types, and security model.

### 4.3. Test Suite (`test_dig_tool.py`)
-   [ ] **Setup:** Create pytest fixtures for the `DigTool` instance.
-   [ ] **Security Tests:**
    -   [ ] Test that invalid domain names (e.g., IP addresses, domains with invalid characters) are rejected.
    -   [ ] Test that disallowed flags (e.g., `-x` for reverse lookups, `-f` for file-based queries) are rejected.
    -   [ ] Test that disallowed query types (e.g., `ANY`) are rejected.
    -   [ ] Test that shell metacharacters are blocked by the base class.
-   [ ] **Functionality Tests:**
    -   [ ] Test a basic `A` record lookup.
    -   [ ] Test lookups for other allowed types (`MX`, `TXT`).
    -   [ ] Test the usage of a safe flag like `+short`.
-   [ ] **Output Parsing Tests:**
    -   [ ] Test that the `_parse_dig_output` method correctly parses various `dig` outputs into the expected structured format.
    -   [ ] Test that the final `ToolOutput` contains the `parsed_results` in its metadata.

## 5. Validation of Plan

This plan is comprehensive and addresses all requirements. It correctly identifies the need for custom target validation as the primary challenge and outlines a clear strategy to implement it. The inclusion of structured output parsing adds significant value to the tool, making it more than just a simple command wrapper. The testing strategy is robust, covering both security and functionality. This plan provides a clear and safe path to implementation.
