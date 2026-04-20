FROM python:3.11-slim

# curl is needed for the HEALTHCHECK; keep the image slim and skip the
# compiler since all Python dependencies are wheels on linux/amd64 and
# linux/arm64.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl tzdata \
    && rm -rf /var/lib/apt/lists/*

# Pin the container timezone to UTC so timestamps produced in Python match
# SQLite's CURRENT_TIMESTAMP (which is always UTC). The Python code also
# normalises to naive-UTC via utcnow(), so TZ-aware hosts can't skew data.
ENV TZ=UTC \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ ./templates/
COPY static/ ./static/

RUN mkdir -p /app/data

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Single worker + threads: SQLite doesn't support multi-process writes,
# and the background collector must run in exactly one process.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "120", "app:app"]
