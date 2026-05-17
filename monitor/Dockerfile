FROM python:3.11-slim

# libpcap is required by Scapy for live packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python3", "sniffer.py"]
