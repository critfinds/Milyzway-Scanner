FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 scanner && \
    mkdir -p /opt/vulnscanner /opt/vulnscanner/results /opt/vulnscanner/logs && \
    chown -R scanner:scanner /opt/vulnscanner

WORKDIR /opt/vulnscanner

# Copy project files
COPY --chown=scanner:scanner pyproject.toml ./
COPY --chown=scanner:scanner scanner ./scanner/
COPY --chown=scanner:scanner tests ./tests/
COPY --chown=scanner:scanner config.yml ./

# Switch to non-root user
USER scanner

# Install Python dependencies
RUN pip install --no-cache-dir --user -e .

# Install Playwright browsers (as user)
RUN /home/scanner/.local/bin/playwright install chromium

# Add user's local bin to PATH
ENV PATH="/home/scanner/.local/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    TZ=UTC

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import scanner; print('OK')" || exit 1

# Default command (can be overridden)
ENTRYPOINT ["python", "-m", "scanner.app"]
CMD ["--config", "config.yml", "--help"]
