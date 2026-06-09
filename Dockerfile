FROM public.ecr.aws/docker/library/python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iptables \
    dnsutils \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/* \
    && curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip

# Copy source and install Python dependencies
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir .

# Install Playwright browsers
RUN playwright install --with-deps chromium

# Copy runtime configs, scripts, and tests
COPY engagements/ engagements/
COPY scripts/ scripts/
COPY tests/ tests/

# Build provenance — baked into the image so scans can record what code ran
ARG GIT_SHA=unknown
ARG IMAGE_TAG=unknown
ENV GIT_SHA=${GIT_SHA}
ENV IMAGE_TAG=${IMAGE_TAG}

# Create non-root user for scanning (iptables still needs NET_ADMIN cap)
RUN useradd -m diana
USER diana

EXPOSE 8000

ENTRYPOINT ["diana"]
CMD ["--help"]
