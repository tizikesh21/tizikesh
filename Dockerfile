FROM python:3.11-slim AS builder
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.11-slim AS telemt
ARG TARGETARCH
ARG TELEMT_VERSION=3.5.17
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && case "$TARGETARCH" in \
        amd64) TELEMT_ARCH=x86_64; TELEMT_SHA256=f1591635849e0aad31f147692b21726da2f49499aae3ece79f8760c92925133a ;; \
        arm64) TELEMT_ARCH=aarch64; TELEMT_SHA256=c80b0159b41cf410b2a87cf62676d67a16a537bd7207602b60dd9ce56e14d1f6 ;; \
        *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSL --retry 5 -o /tmp/telemt.tar.gz "https://github.com/telemt/telemt/releases/download/${TELEMT_VERSION}/telemt-${TELEMT_ARCH}-linux-musl.tar.gz" \
    && echo "${TELEMT_SHA256}  /tmp/telemt.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/telemt.tar.gz -C /tmp \
    && install -m 0755 /tmp/telemt /usr/local/bin/telemt \
    && mkdir -p /usr/local/share/telemt \
    && curl -fsSL --retry 5 -o /usr/local/share/telemt/LICENSE "https://raw.githubusercontent.com/telemt/telemt/${TELEMT_VERSION}/LICENSE" \
    && /usr/local/bin/telemt --version \
    && rm -f /tmp/telemt.tar.gz /tmp/telemt

FROM python:3.11-slim
WORKDIR /app
ENV HOME=/home/sulgx \
    PATH=/home/sulgx/.local/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        gosu ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m sulgx && chown -R sulgx:sulgx /app
RUN mkdir -p /data && chown -R sulgx:sulgx /data
COPY --from=builder /root/.local /home/sulgx/.local
RUN chown -R sulgx:sulgx /home/sulgx/.local
COPY --from=telemt /usr/local/bin/telemt /usr/local/bin/telemt
COPY --from=telemt /usr/local/share/telemt/LICENSE /usr/local/share/telemt/LICENSE
COPY --chown=sulgx:sulgx . .
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import os,urllib.request; port=os.environ.get('PORT','8000'); urllib.request.urlopen(f'http://localhost:{port}/health')"
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python", "main.py"]
