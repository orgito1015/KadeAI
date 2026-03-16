FROM python:3.12-slim

# System tools for all CTF categories
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Reversing / Pwn
    binutils \
    gdb \
    ltrace \
    strace \
    # Forensics
    file \
    xxd \
    binwalk \
    tshark \
    exiftool \
    steghide \
    zsteg \
    outguess \
    # Crypto
    hashcat \
    john \
    # Web
    curl \
    netcat-openbsd \
    # General
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install checksec
RUN curl -sL https://github.com/slimm609/checksec.sh/releases/latest/download/checksec \
    -o /usr/local/bin/checksec && chmod +x /usr/local/bin/checksec

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root for safety
RUN useradd -m ctf
USER ctf

ENTRYPOINT ["python3", "server.py"]
