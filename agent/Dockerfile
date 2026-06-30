FROM python:3.12-slim

LABEL maintainer="AEGIS Defense Platform"
LABEL description="AEGIS EDR-lite Endpoint Agent"

# System deps for psutil (gcc needed to compile C extension)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r aegis && useradd -r -g aegis -d /opt/aegis -s /sbin/nologin aegis

WORKDIR /opt/aegis

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y gcc python3-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Copy agent source
COPY config.py .
COPY aegis_agent.py .

# The agent needs to write .agent_id file
RUN chown -R aegis:aegis /opt/aegis

USER aegis

# Environment variables (override at runtime)
ENV AEGIS_API_URL="http://localhost:8000/api/v1"
ENV AEGIS_API_KEY=""
ENV AEGIS_LOG_LEVEL="INFO"
ENV AEGIS_BREADCRUMBS_ENABLED="true"

# Health check: verify the process is running
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD pgrep -f aegis_agent.py || exit 1

CMD ["python", "-u", "aegis_agent.py"]
