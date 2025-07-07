# Multi-stage Docker build for ReconCLI
FROM python:3.11-slim-bullseye as builder

# Set working directory
WORKDIR /app

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
   build-essential \
   curl \
   wget \
   git \
   golang-go \
   && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements*.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
   && pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install ReconCLI
RUN pip install -e .

# Production stage
FROM python:3.11-slim-bullseye

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
   nmap \
   dnsutils \
   curl \
   wget \
   git \
   sqlmap \
   ca-certificates \
   && rm -rf /var/lib/apt/lists/*

# Install Go (needed for some security tools)
RUN curl -L https://golang.org/dl/go1.21.3.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"

# Create non-root user
RUN useradd -m -s /bin/bash recon

# Set working directory
WORKDIR /app

# Copy Python environment from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

# Install Go-based security tools
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
   go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
   go install github.com/tomnomnom/gf@latest && \
   go install github.com/lc/gau/v2/cmd/gau@latest && \
   go install github.com/ffuf/ffuf@latest && \
   go install github.com/projectdiscovery/katana/cmd/katana@latest && \
   mv /root/go/bin/* /usr/local/bin/ && \
   rm -rf /root/go

# Install additional Python tools
RUN pip install --no-cache-dir ghauri

# Create output directory
RUN mkdir -p /app/output && chown -R recon:recon /app/output

# Switch to non-root user
USER recon

# Set environment variables
ENV PYTHONPATH="/app:${PYTHONPATH}"
ENV PATH="/usr/local/bin:${PATH}"

# Create aliases and helper scripts
RUN echo 'alias reconcli="python -m reconcli"' >> ~/.bashrc && \
   echo 'alias vulnsqlicli="python -m reconcli vulnsqlicli"' >> ~/.bashrc && \
   echo 'alias dirbcli="python -m reconcli dirbcli"' >> ~/.bashrc && \
   echo 'alias vhostcli="python -m reconcli vhostcli"' >> ~/.bashrc

# Expose default port (if needed for web interface in future)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
   CMD python -c "import reconcli; print('ReconCLI is healthy')" || exit 1

# Default command
ENTRYPOINT ["python", "-m", "reconcli"]
CMD ["--help"]

# Labels for metadata
LABEL maintainer="Jarek Bir <jarek@example.com>"
LABEL description="ReconCLI - Advanced modular reconnaissance toolkit"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/jarek-bir/Reconcli"
LABEL org.opencontainers.image.documentation="https://github.com/jarek-bir/Reconcli/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"
