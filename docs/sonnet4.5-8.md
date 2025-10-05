# Continuing Complete Implementation - Docker Files

## File 3: Dockerfile

```dockerfile
#==============================================================================
# MCP Network Tools Server - Multi-Stage Dockerfile
#==============================================================================
# Purpose: Optimized, secure container image with multi-stage build
#
# Build:
#   docker build -t mcp-server:latest .
#
# Run:
#   docker run --rm mcp-server:latest
#
# Security Features:
#   - Non-root user (mcp:mcp)
#   - Minimal attack surface
#   - No unnecessary tools
#   - Security scanning friendly
#   - Read-only root filesystem support
#
# Author: MCP Network Tools Team
# Version: 2.0.0
#==============================================================================

#------------------------------------------------------------------------------
# Stage 1: Builder
#------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

# Build arguments
ARG PYTHON_VERSION=3.11
ARG DEBIAN_FRONTEND=noninteractive

# Labels
LABEL stage=builder
LABEL description="Builder stage for MCP Server"

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    make \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create build directory
WORKDIR /build

# Copy requirements first (for layer caching)
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . /build/

# Install application in editable mode (for development)
# For production, use: pip install .
RUN /opt/venv/bin/pip install --no-cache-dir -e .

# Compile Python files to bytecode for faster startup
RUN /opt/venv/bin/python -m compileall /build/mcp_server

#------------------------------------------------------------------------------
# Stage 2: Runtime
#------------------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS runtime

# Build arguments
ARG DEBIAN_FRONTEND=noninteractive
ARG MCP_USER=mcp
ARG MCP_UID=1000
ARG MCP_GID=1000

# Metadata labels
LABEL maintainer="MCP Network Tools Team"
LABEL version="2.0.0"
LABEL description="Production-ready MCP server for network security tools"
LABEL org.opencontainers.image.title="MCP Network Tools Server"
LABEL org.opencontainers.image.description="Secure, monitored network tool execution via MCP protocol"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.vendor="MCP Network Tools Team"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/your-org/mcp-network-tools"

# Install runtime dependencies only (minimal footprint)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools
    nmap \
    netcat-openbsd \
    iputils-ping \
    # Process management
    tini \
    # Certificate management
    ca-certificates \
    # Useful utilities
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user and group
RUN groupadd -g ${MCP_GID} ${MCP_USER} && \
    useradd -u ${MCP_UID} -g ${MCP_GID} -m -s /bin/bash ${MCP_USER}

# Create application directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder --chown=${MCP_USER}:${MCP_USER} /opt/venv /opt/venv

# Copy application from builder
COPY --from=builder --chown=${MCP_USER}:${MCP_USER} /build /app

# Copy Docker support scripts
COPY --chown=${MCP_USER}:${MCP_USER} docker/entrypoint.sh /app/docker/entrypoint.sh
COPY --chown=${MCP_USER}:${MCP_USER} docker/healthcheck.sh /app/docker/healthcheck.sh

# Make scripts executable
RUN chmod +x /app/docker/entrypoint.sh /app/docker/healthcheck.sh

# Create directories for runtime data
RUN mkdir -p /app/logs /app/data /app/config && \
    chown -R ${MCP_USER}:${MCP_USER} /app/logs /app/data /app/config

# Set PATH to include virtual environment
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Python optimizations
    PYTHONOPTIMIZE=1 \
    # Application settings
    MCP_HOME=/app \
    MCP_LOG_DIR=/app/logs \
    MCP_DATA_DIR=/app/data \
    MCP_CONFIG_DIR=/app/config

# Switch to non-root user
USER ${MCP_USER}

# Expose ports (8080 for HTTP mode)
EXPOSE 8080

# Health check (HTTP mode only - will fail gracefully in stdio mode)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/app/docker/healthcheck.sh"]

# Use tini as init system for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker/entrypoint.sh"]

# Default command (can be overridden)
CMD ["python", "-m", "mcp_server.server"]

#==============================================================================
# Build Information
#==============================================================================
# Build context: Project root directory
# Image size optimization:
#   - Multi-stage build reduces final image size
#   - Only runtime dependencies included
#   - Layer caching optimized with requirements first
#   - Bytecode compilation for faster startup
#
# Security:
#   - Non-root user (UID 1000)
#   - Minimal attack surface (slim base, only needed tools)
#   - No shell in production use
#   - Tini for zombie process prevention
#
# Usage:
#   docker build -t mcp-server:latest .
#   docker run --rm -e MCP_SERVER_TRANSPORT=http mcp-server:latest
#==============================================================================
```

## File 4: docker-compose.yml

```yaml
#==============================================================================
# MCP Network Tools Server - Docker Compose Configuration
#==============================================================================
# Purpose: Production-ready container orchestration
#
# Usage:
#   docker-compose up -d                 # Start in background
#   docker-compose logs -f               # Follow logs
#   docker-compose ps                    # Show status
#   docker-compose down                  # Stop and remove
#
# Environment:
#   Use .env.docker file for environment variables
#   Override with docker-compose.override.yml for development
#
# Author: MCP Network Tools Team
# Version: 2.0.0
#==============================================================================

version: '3.8'

#------------------------------------------------------------------------------
# Services
#------------------------------------------------------------------------------
services:
  
  #----------------------------------------------------------------------------
  # MCP Server Service
  #----------------------------------------------------------------------------
  mcp-server:
    image: mcp-server:latest
    container_name: mcp-server
    
    # Build configuration
    build:
      context: .
      dockerfile: Dockerfile
      args:
        - PYTHON_VERSION=3.11
        - MCP_USER=mcp
        - MCP_UID=1000
        - MCP_GID=1000
      labels:
        - "com.mcp.project=network-tools"
        - "com.mcp.version=2.0.0"
    
    # Restart policy for production reliability
    restart: unless-stopped
    
    # Environment variables (use .env.docker file)
    env_file:
      - .env.docker
    
    environment:
      # Server configuration
      - MCP_SERVER_TRANSPORT=${MCP_SERVER_TRANSPORT:-http}
      - MCP_SERVER_HOST=${MCP_SERVER_HOST:-0.0.0.0}
      - MCP_SERVER_PORT=${MCP_SERVER_PORT:-8080}
      - MCP_SERVER_SHUTDOWN_GRACE_PERIOD=${MCP_SERVER_SHUTDOWN_GRACE_PERIOD:-30}
      
      # Security settings
      - MCP_SECURITY_ALLOW_INTRUSIVE=${MCP_SECURITY_ALLOW_INTRUSIVE:-false}
      - MCP_SECURITY_MAX_ARGS_LENGTH=${MCP_SECURITY_MAX_ARGS_LENGTH:-2048}
      - MCP_SECURITY_TIMEOUT_SECONDS=${MCP_SECURITY_TIMEOUT_SECONDS:-300}
      - MCP_SECURITY_CONCURRENCY_LIMIT=${MCP_SECURITY_CONCURRENCY_LIMIT:-2}
      
      # Tool configuration
      - MCP_TOOL_DEFAULT_TIMEOUT=${MCP_TOOL_DEFAULT_TIMEOUT:-300}
      - MCP_TOOL_DEFAULT_CONCURRENCY=${MCP_TOOL_DEFAULT_CONCURRENCY:-2}
      
      # Circuit breaker
      - MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD=${MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD:-5}
      - MCP_CIRCUIT_BREAKER_RECOVERY_TIMEOUT=${MCP_CIRCUIT_BREAKER_RECOVERY_TIMEOUT:-60}
      
      # Health monitoring
      - MCP_HEALTH_CHECK_INTERVAL=${MCP_HEALTH_CHECK_INTERVAL:-30}
      - MCP_HEALTH_CPU_THRESHOLD=${MCP_HEALTH_CPU_THRESHOLD:-80}
      - MCP_HEALTH_MEMORY_THRESHOLD=${MCP_HEALTH_MEMORY_THRESHOLD:-80}
      - MCP_HEALTH_DISK_THRESHOLD=${MCP_HEALTH_DISK_THRESHOLD:-80}
      
      # Metrics
      - MCP_METRICS_ENABLED=${MCP_METRICS_ENABLED:-true}
      - MCP_METRICS_PROMETHEUS_PORT=${MCP_METRICS_PROMETHEUS_PORT:-9090}
      
      # Logging
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
      - LOG_FORMAT=${LOG_FORMAT:-%(asctime)s - %(name)s - %(levelname)s - %(message)s}
    
    # Port mappings (HTTP mode)
    ports:
      - "${MCP_SERVER_PORT:-8080}:8080"
      - "${MCP_METRICS_PROMETHEUS_PORT:-9090}:9090"
    
    # Volume mounts
    volumes:
      # Configuration
      - type: bind
        source: ${MCP_CONFIG_DIR:-./config}
        target: /app/config
        read_only: true
      
      # Persistent data
      - type: volume
        source: mcp-data
        target: /app/data
      
      # Logs
      - type: volume
        source: mcp-logs
        target: /app/logs
    
    # Network configuration
    networks:
      - mcp-network
    
    # Resource limits (production)
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M
    
    # Health check
    healthcheck:
      test: ["CMD", "/app/docker/healthcheck.sh"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    
    # Security options
    security_opt:
      - no-new-privileges:true
    
    # Capabilities (drop all, add only needed)
    cap_drop:
      - ALL
    cap_add:
      - NET_RAW  # Required for nmap
      - NET_ADMIN  # Required for some network operations
    
    # Read-only root filesystem (with tmpfs for /tmp)
    read_only: false  # Set to true if application supports it
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=100m
    
    # DNS configuration (optional)
    dns:
      - 8.8.8.8
      - 8.8.4.4
    
    # Logging driver
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "com.mcp.project,com.mcp.version"
    
    # Labels for organization
    labels:
      com.mcp.project: "network-tools"
      com.mcp.version: "2.0.0"
      com.mcp.component: "server"
      com.mcp.environment: "production"

#------------------------------------------------------------------------------
# Networks
#------------------------------------------------------------------------------
networks:
  mcp-network:
    name: mcp-network
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
    labels:
      com.mcp.project: "network-tools"

#------------------------------------------------------------------------------
# Volumes
#------------------------------------------------------------------------------
volumes:
  # Persistent data storage
  mcp-data:
    name: mcp-data
    driver: local
    labels:
      com.mcp.project: "network-tools"
      com.mcp.component: "data"
  
  # Log storage
  mcp-logs:
    name: mcp-logs
    driver: local
    labels:
      com.mcp.project: "network-tools"
      com.mcp.component: "logs"

#==============================================================================
# Configuration Notes
#==============================================================================
# 
# Environment Variables:
#   - Define in .env.docker file (not committed to git)
#   - Override with environment-specific values
#   - Use docker-compose.override.yml for local development
#
# Resource Limits:
#   - Adjust based on your workload
#   - Monitor with: docker stats mcp-server
#
# Networking:
#   - Bridge network for isolation
#   - Expose only necessary ports
#   - Use internal networks for multi-service deployments
#
# Volumes:
#   - mcp-data: Persistent application data
#   - mcp-logs: Application logs (rotated)
#   - Configuration mounted read-only
#
# Security:
#   - Non-root user in container
#   - Minimal capabilities
#   - Read-only root filesystem (when possible)
#   - No new privileges
#
# Health Checks:
#   - Automatic container restart on failure
#   - Graceful degradation
#   - Monitoring integration ready
#
# Logging:
#   - JSON format for log aggregation
#   - Automatic rotation (10MB max, 3 files)
#   - Labels for filtering
#
#==============================================================================
```

## File 5: docker-compose.override.yml

```yaml
#==============================================================================
# MCP Network Tools Server - Development Override
#==============================================================================
# Purpose: Development-friendly configuration overrides
#
# Usage:
#   docker-compose up -d    # Automatically merges with docker-compose.yml
#
# Features:
#   - Source code hot-reload
#   - Debug mode enabled
#   - Relaxed resource limits
#   - Additional logging
#   - Development tools available
#
# Note: This file is automatically used by docker-compose.
#       For production, use: docker-compose -f docker-compose.yml up -d
#
# Author: MCP Network Tools Team
# Version: 2.0.0
#==============================================================================

version: '3.8'

services:
  
  #----------------------------------------------------------------------------
  # MCP Server - Development Overrides
  #----------------------------------------------------------------------------
  mcp-server:
    
    # Build with development tags
    build:
      context: .
      dockerfile: Dockerfile
      target: runtime  # Can specify different target if needed
      labels:
        - "com.mcp.environment=development"
    
    # Development environment variables
    environment:
      # Enable debug mode
      - LOG_LEVEL=DEBUG
      - PYTHONUNBUFFERED=1
      - PYTHONDONTWRITEBYTECODE=1
      
      # Development server settings
      - MCP_SERVER_TRANSPORT=http
      - MCP_SERVER_HOST=0.0.0.0
      - MCP_SERVER_PORT=8080
      
      # Relaxed security for testing
      - MCP_SECURITY_ALLOW_INTRUSIVE=true  # DEVELOPMENT ONLY!
      
      # Faster circuit breaker recovery for testing
      - MCP_CIRCUIT_BREAKER_RECOVERY_TIMEOUT=30
      
      # More frequent health checks
      - MCP_HEALTH_CHECK_INTERVAL=15
      
      # Enable all metrics
      - MCP_METRICS_ENABLED=true
      - MCP_METRICS_PROMETHEUS_ENABLED=true
    
    # Mount source code for hot-reload
    volumes:
      # Source code (read-write for development)
      - type: bind
        source: ./mcp_server
        target: /app/mcp_server
      
      # Tests (for running tests in container)
      - type: bind
        source: ./tests
        target: /app/tests
      
      # Configuration (read-write for testing)
      - type: bind
        source: ${MCP_CONFIG_DIR:-./config}
        target: /app/config
      
      # Requirements (for dependency changes)
      - type: bind
        source: ./requirements.txt
        target: /app/requirements.txt
        read_only: true
      
      # Persistent data (local directory)
      - type: bind
        source: ./data
        target: /app/data
      
      # Logs (local directory for easy access)
      - type: bind
        source: ./logs
        target: /app/logs
    
    # Additional port exposures for debugging
    ports:
      - "8080:8080"   # HTTP API
      - "9090:9090"   # Prometheus metrics
      - "5678:5678"   # Python debugger (debugpy)
    
    # Relaxed resource limits for development
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 512M
    
    # More lenient health check for development
    healthcheck:
      test: ["CMD", "/app/docker/healthcheck.sh"]
      interval: 60s
      timeout: 15s
      retries: 5
      start_period: 30s
    
    # Enable all capabilities for debugging (DEVELOPMENT ONLY!)
    cap_add:
      - NET_RAW
      - NET_ADMIN
      - SYS_PTRACE  # For debugging
    
    # Disable read-only filesystem for development
    read_only: false
    
    # Additional tmpfs mounts
    tmpfs:
      - /tmp:rw,exec,size=500m  # Larger, exec allowed for testing
    
    # Development-specific labels
    labels:
      com.mcp.environment: "development"
      com.mcp.hot-reload: "enabled"
      com.mcp.debug: "enabled"
    
    # Override command for development with auto-reload
    # Uncomment to use watchdog for auto-reload:
    # command: >
    #   sh -c "pip install watchdog &&
    #          watchmedo auto-restart
    #          --directory=/app/mcp_server
    #          --pattern='*.py'
    #          --recursive
    #          -- python -m mcp_server.server"
    
    # Standard command (manual restart required)
    command: ["python", "-m", "mcp_server.server"]

  #----------------------------------------------------------------------------
  # Optional: Development Database (if needed)
  #----------------------------------------------------------------------------
  # postgres:
  #   image: postgres:15-alpine
  #   container_name: mcp-postgres-dev
  #   environment:
  #     - POSTGRES_DB=mcp_dev
  #     - POSTGRES_USER=mcp
  #     - POSTGRES_PASSWORD=mcp_dev_pass
  #   ports:
  #     - "5432:5432"
  #   volumes:
  #     - postgres-data:/var/lib/postgresql/data
  #   networks:
  #     - mcp-network
  #   labels:
  #     com.mcp.environment: "development"

  #----------------------------------------------------------------------------
  # Optional: Redis Cache (if needed)
  #----------------------------------------------------------------------------
  # redis:
  #   image: redis:7-alpine
  #   container_name: mcp-redis-dev
  #   ports:
  #     - "6379:6379"
  #   networks:
  #     - mcp-network
  #   labels:
  #     com.mcp.environment: "development"

#------------------------------------------------------------------------------
# Development Volumes
#------------------------------------------------------------------------------
# volumes:
#   postgres-data:
#     name: mcp-postgres-dev-data

#==============================================================================
# Development Notes
#==============================================================================
#
# Hot Reload:
#   - Source code is mounted as volume
#   - Changes reflect immediately (may need manual restart)
#   - Use watchdog for automatic restart on file changes
#
# Debugging:
#   - Port 5678 exposed for debugpy (Python debugger)
#   - Attach with VS Code or PyCharm
#   - Set breakpoints in mounted source code
#
# Testing:
#   - Run tests inside container:
#     docker-compose exec mcp-server pytest
#   - Tests directory is mounted
#
# Database Access (if enabled):
#   - PostgreSQL: localhost:5432
#   - Redis: localhost:6379
#   - Credentials in environment section
#
# Logs:
#   - Available at ./logs/ directory
#   - Real-time: docker-compose logs -f mcp-server
#   - DEBUG level enabled
#
# Security Warning:
#   - INTRUSIVE mode enabled for testing
#   - DO NOT use this configuration in production!
#   - Additional capabilities enabled
#
# Resource Usage:
#   - Higher limits for development
#   - Monitor with: docker stats
#
# Cleanup:
#   - Stop: docker-compose down
#   - Remove volumes: docker-compose down -v
#   - Clean rebuild: docker-compose build --no-cache
#
#==============================================================================
```

## File 6: .dockerignore

```gitignore
#==============================================================================
# Docker Build Context Exclusions
#==============================================================================
# Purpose: Optimize Docker build context and image size
#
# Benefits:
#   - Faster builds (smaller context)
#   - Smaller images (excluded from COPY)
#   - Better security (no sensitive files)
#   - Cleaner builds (no temporary files)
#
# Author: MCP Network Tools Team
# Version: 2.0.0
#==============================================================================

#------------------------------------------------------------------------------
# Python
#------------------------------------------------------------------------------

# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/
cover/

# Translations
*.mo
*.pot

# Django stuff:
*.log
local_settings.py
db.sqlite3
db.sqlite3-journal

# Flask stuff:
instance/
.webassets-cache

# Scrapy stuff:
.scrapy

# Sphinx documentation
docs/_build/

# PyBuilder
.pybuilder/
target/

# Jupyter Notebook
.ipynb_checkpoints

# IPython
profile_default/
ipython_config.py

# pyenv
.python-version

# pipenv
Pipfile.lock

# poetry
poetry.lock

# pdm
.pdm.toml

# PEP 582
__pypackages__/

# Celery stuff
celerybeat-schedule
celerybeat.pid

# SageMath parsed files
*.sage.py

# Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# Spyder project settings
.spyderproject
.spyproject

# Rope project settings
.ropeproject

# mkdocs documentation
/site

# mypy
.mypy_cache/
.dmypy.json
dmypy.json

# Pyre type checker
.pyre/

# pytype static type analyzer
.pytype/

# Cython debug symbols
cython_debug/

#------------------------------------------------------------------------------
# IDEs and Editors
#------------------------------------------------------------------------------

# VS Code
.vscode/
*.code-workspace

# PyCharm
.idea/
*.iml
*.iws
.idea_modules/

# Sublime Text
*.sublime-project
*.sublime-workspace

# Vim
*.swp
*.swo
*~
.vim/

# Emacs
*~
\#*\#
.\#*

# Atom
.atom/

#------------------------------------------------------------------------------
# Operating Systems
#------------------------------------------------------------------------------

# macOS
.DS_Store
.AppleDouble
.LSOverride
._*

# Windows
Thumbs.db
Thumbs.db:encryptable
ehthumbs.db
ehthumbs_vista.db
*.stackdump
[Dd]esktop.ini
$RECYCLE.BIN/

# Linux
*~
.directory
.Trash-*

#------------------------------------------------------------------------------
# Version Control
#------------------------------------------------------------------------------

# Git
.git/
.gitignore
.gitattributes
.gitmodules

# SVN
.svn/

# Mercurial
.hg/
.hgignore
.hgtags

#------------------------------------------------------------------------------
# CI/CD
#------------------------------------------------------------------------------

# GitHub Actions
.github/

# GitLab CI
.gitlab-ci.yml

# Jenkins
Jenkinsfile

# CircleCI
.circleci/

# Travis CI
.travis.yml

#------------------------------------------------------------------------------
# Docker
#------------------------------------------------------------------------------

# Docker files (don't include in context recursively)
Dockerfile*
docker-compose*.yml
.dockerignore

# Docker volumes and data
data/
volumes/

#------------------------------------------------------------------------------
# Logs and Temporary Files
#------------------------------------------------------------------------------

# Logs
logs/
*.log
*.log.*
*.out

# Temporary files
tmp/
temp/
*.tmp
*.temp
*.bak
*.backup
*.swp
*.swo

# OS temp files
.DS_Store
Thumbs.db

#------------------------------------------------------------------------------
# Project-Specific
#------------------------------------------------------------------------------

# Documentation
docs/
*.md
!README.md  # Include README in image
LICENSE
CONTRIBUTING.md
CHANGELOG.md

# Configuration (use environment variables instead)
config/*.local.yml
config/*.local.yaml
config/*.local.json
*.secret.*
.env.*

# Test files
tests/
test_*.py
*_test.py
*.test.py

# Scripts (include only necessary ones)
scripts/
*.sh
!docker/*.sh  # Include Docker scripts

# Development tools
.editorconfig
.prettierrc
.eslintrc
.pylintrc
pyrightconfig.json
setup.cfg

# Database files
*.db
*.sqlite
*.sqlite3

# Media and large files
*.jpg
*.jpeg
*.png
*.gif
*.pdf
*.mp4
*.avi
*.mov

# Archives
*.zip
*.tar
*.tar.gz
*.tgz
*.rar
*.7z

# Node modules (if any frontend)
node_modules/
package-lock.json
yarn.lock

# Go (if any Go tools)
vendor/
go.sum

# Rust (if any Rust tools)
target/
Cargo.lock

#------------------------------------------------------------------------------
# Security and Secrets
#------------------------------------------------------------------------------

# Secrets and credentials
*.pem
*.key
*.cert
*.crt
*.p12
*.pfx
secrets/
.secrets/
credentials/
.aws/
.ssh/

# API keys and tokens
.env
.env.local
.env.production
.env.development
*.env

#------------------------------------------------------------------------------
# Monitoring and Profiling
#------------------------------------------------------------------------------

# Profiling data
*.prof
*.pprof
*.trace

# Monitoring data
prometheus/
grafana/

#==============================================================================
# Notes
#==============================================================================
#
# Build Context Optimization:
#   - Exclude everything not needed for the build
#   - Reduces context upload time
#   - Speeds up builds significantly
#
# Security:
#   - No secrets or credentials in image
#   - No sensitive configuration files
#   - No development tools in production image
#
# Image Size:
#   - Smaller context = faster builds
#   - Excluded files don't increase image size
#   - Better layer caching
#
# Maintenance:
#   - Keep this file updated
#   - Review periodically
#   - Document exceptions with comments
#
#==============================================================================
```

## File 7: .env.docker

```bash
#==============================================================================
# MCP Network Tools Server - Docker Environment Configuration
#==============================================================================
# Purpose: Environment variables for Docker deployment
#
# Usage:
#   1. Copy this file: cp .env.docker .env
#   2. Edit values for your environment
#   3. Do NOT commit .env file to git (contains secrets)
#   4. Use docker-compose up -d
#
# Security:
#   - Keep this file secure
#   - Use secrets management for production
#   - Rotate credentials regularly
#
# Author: MCP Network Tools Team
# Version: 2.0.0
#==============================================================================

#------------------------------------------------------------------------------
# Server Configuration
#------------------------------------------------------------------------------

# Transport mode: stdio or http
# - stdio: For AI agent integration (Claude Desktop, etc.)
# - http: For API access, monitoring, distributed deployments
MCP_SERVER_TRANSPORT=http

# HTTP server settings (only used if transport=http)
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8080
MCP_SERVER_WORKERS=1
MCP_SERVER_MAX_CONNECTIONS=100

# Graceful shutdown timeout (seconds)
MCP_SERVER_SHUTDOWN_GRACE_PERIOD=30

#------------------------------------------------------------------------------
# Security Settings
#------------------------------------------------------------------------------

# Allow intrusive operations (nmap -A, vulnerability scripts)
# WARNING: Only enable in controlled environments!
# Values: true, false
MCP_SECURITY_ALLOW_INTRUSIVE=false

# Allowed target patterns (comma-separated)
# Default: RFC1918 private IPs and .lab.internal domains
# MCP_SECURITY_ALLOWED_TARGETS=RFC1918,.lab.internal

# Maximum argument length (bytes)
MCP_SECURITY_MAX_ARGS_LENGTH=2048

# Maximum output size (bytes)
MCP_SECURITY_MAX_OUTPUT_SIZE=1048576

# Default timeout for operations (seconds)
MCP_SECURITY_TIMEOUT_SECONDS=300

# Concurrent operation limit
MCP_SECURITY_CONCURRENCY_LIMIT=2

#------------------------------------------------------------------------------
# Tool Configuration
#------------------------------------------------------------------------------

# Default timeout for tool execution (seconds)
MCP_TOOL_DEFAULT_TIMEOUT=300

# Default concurrency per tool
MCP_TOOL_DEFAULT_CONCURRENCY=2

# Tool inclusion/exclusion (comma-separated)
# Example: TOOL_INCLUDE=NmapTool,PingTool
# TOOL_INCLUDE=
# TOOL_EXCLUDE=

# Tools package to scan
TOOLS_PACKAGE=mcp_server.tools

#------------------------------------------------------------------------------
# Circuit Breaker Configuration
#------------------------------------------------------------------------------

# Failure threshold before opening circuit
MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD=5

# Recovery timeout (seconds)
MCP_CIRCUIT_BREAKER_RECOVERY_TIMEOUT=60

# Success threshold to close circuit from half-open
MCP_CIRCUIT_BREAKER_HALF_OPEN_SUCCESS_THRESHOLD=1

#------------------------------------------------------------------------------
# Health Check Configuration
#------------------------------------------------------------------------------

# Health check interval (seconds)
MCP_HEALTH_CHECK_INTERVAL=30.0

# CPU usage threshold (percentage)
MCP_HEALTH_CPU_THRESHOLD=80.0

# Memory usage threshold (percentage)
MCP_HEALTH_MEMORY_THRESHOLD=80.0

# Disk usage threshold (percentage)
MCP_HEALTH_DISK_THRESHOLD=80.0

# Health check timeout (seconds)
MCP_HEALTH_TIMEOUT=10.0

# Dependencies to check (comma-separated Python packages)
# Example: MCP_HEALTH_DEPENDENCIES=psutil,prometheus_client
MCP_HEALTH_DEPENDENCIES=

#------------------------------------------------------------------------------
# Metrics Configuration
#------------------------------------------------------------------------------

# Enable metrics collection
MCP_METRICS_ENABLED=true

# Enable Prometheus metrics endpoint
MCP_METRICS_PROMETHEUS_ENABLED=true

# Prometheus metrics port
MCP_METRICS_PROMETHEUS_PORT=9090

# Metrics collection interval (seconds)
MCP_METRICS_COLLECTION_INTERVAL=15.0

#------------------------------------------------------------------------------
# Logging Configuration
#------------------------------------------------------------------------------

# Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL=INFO

# Log format
LOG_FORMAT=%(asctime)s - %(name)s - %(levelname)s - %(message)s

# Log file path (optional, logs to stdout by default)
# MCP_LOGGING_FILE_PATH=/app/logs/mcp_server.log

# Maximum log file size (bytes)
MCP_LOGGING_MAX_FILE_SIZE=10485760

# Number of backup log files
MCP_LOGGING_BACKUP_COUNT=5

#------------------------------------------------------------------------------
# Database Configuration (if needed)
#------------------------------------------------------------------------------

# Database URL (PostgreSQL example)
# MCP_DATABASE_URL=postgresql://user:password@postgres:5432/mcp_db

# Connection pool settings
# MCP_DATABASE_POOL_SIZE=10
# MCP_DATABASE_MAX_OVERFLOW=20
# MCP_DATABASE_POOL_TIMEOUT=30
# MCP_DATABASE_POOL_RECYCLE=3600

#------------------------------------------------------------------------------
# Configuration File
#------------------------------------------------------------------------------

# Path to configuration file (YAML or JSON)
# Overrides environment variables if specified
# MCP_CONFIG_FILE=/app/config/config.yaml

# Configuration directory
MCP_CONFIG_DIR=./config

#------------------------------------------------------------------------------
# Resource Limits (for reference, set in docker-compose.yml)
#------------------------------------------------------------------------------

# These are enforced by Docker, not environment variables
# See docker-compose.yml deploy.resources section

# CPU limit: 2.0 cores
# Memory limit: 1GB
# Memory reservation: 256MB

#------------------------------------------------------------------------------
# Network Configuration
#------------------------------------------------------------------------------

# DNS servers (optional, comma-separated)
# MCP_DNS_SERVERS=8.8.8.8,8.8.4.4

#------------------------------------------------------------------------------
# Development Settings (docker-compose.override.yml)
#------------------------------------------------------------------------------

# These settings are typically overridden in docker-compose.override.yml
# for development environments

# Enable debug mode
# DEBUG=false

# Python optimizations
PYTHONUNBUFFERED=1
PYTHONDONTWRITEBYTECODE=1

#==============================================================================
# Environment-Specific Configurations
#==============================================================================

#------------------------------------------------------------------------------
# Production Example
#------------------------------------------------------------------------------
# MCP_SERVER_TRANSPORT=http
# MCP_SECURITY_ALLOW_INTRUSIVE=false
# LOG_LEVEL=INFO
# MCP_METRICS_ENABLED=true
# MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD=5
# MCP_HEALTH_CHECK_INTERVAL=30

#------------------------------------------------------------------------------
# Development Example
#------------------------------------------------------------------------------
# MCP_SERVER_TRANSPORT=http
# MCP_SECURITY_ALLOW_INTRUSIVE=true
# LOG_LEVEL=DEBUG
# MCP_METRICS_ENABLED=true
# MCP_CIRCUIT_BREAKER_RECOVERY_TIMEOUT=30
# MCP_HEALTH_CHECK_INTERVAL=15

#------------------------------------------------------------------------------
# Testing Example
#------------------------------------------------------------------------------
# MCP_SERVER_TRANSPORT=stdio
# MCP_SECURITY_ALLOW_INTRUSIVE=true
# LOG_LEVEL=DEBUG
# MCP_CIRCUIT_BREAKER_FAILURE_THRESHOLD=3
# MCP_TOOL_DEFAULT_TIMEOUT=60

#==============================================================================
# Security Notes
#==============================================================================
#
# Secrets Management:
#   - Use Docker secrets or external secret management (Vault, AWS Secrets Manager)
#   - Never commit .env file with real credentials
#   - Rotate credentials regularly
#   - Use least-privilege principle
#
# File Permissions:
#   - chmod 600 .env (owner read/write only)
#   - Store in secure location
#   - Audit access regularly
#
# Environment Variables vs. Config File:
#   - Environment variables: Dynamic, container-specific
#   - Config file: Static, shared configuration
#   - Environment variables override config file settings
#
#==============================================================================
```

Due to message length, I'll provide the final two files (entrypoint.sh and healthcheck.sh) in my next response!

Would you like me to continue with the Docker scripts now?
