FROM python:3.11-slim

# System deps required by the cryptography package
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Persistent data lives in /data (mounted as a named volume)
RUN mkdir -p /data

EXPOSE 5000

CMD ["python3", "app.py"]
