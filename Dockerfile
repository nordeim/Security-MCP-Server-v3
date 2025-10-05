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
FROM python:3.12-slim-trixie AS builder

# Build arguments
ARG PYTHON_VERSION=3.12
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
