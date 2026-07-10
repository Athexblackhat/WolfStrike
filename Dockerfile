FROM python:3.11-slim

LABEL maintainer="ATHEX BLACK HAT"
LABEL team="Wolf Intelligence PK"
LABEL version="1.0.0"
LABEL description="WOLFSTRIKE - Ultimate Web Penetration Testing Toolkit"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV WOLFSTRIKE_HOME=/opt/wolfstrike

WORKDIR ${WOLFSTRIKE_HOME}

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    curl \
    dnsutils \
    git \
    nmap \
    tor \
    whois \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p logs reports screenshots

ENTRYPOINT ["python3", "wolfstrike.py"]
CMD ["--help"]