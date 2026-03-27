FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY migrate.py .
COPY templates/ ./templates/
COPY static/ ./static/

# Create data directory for database
RUN mkdir -p /app/data

# Create non-root user
#RUN useradd -m -u 1000 vpnstats && \
#    chown -R vpnstats:vpnstats /app
    
#USER vpnstats

# Expose port
EXPOSE 5000

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Single worker + threads: SQLite doesn't support multi-process writes,
# and the background collector must run in exactly one process
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "120", "app:app"]
