FROM python:3.11-slim

# Install Nmap and system dependencies
RUN apt-get update && \
    apt-get install -y nmap sqlite3 && \
    rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your code
COPY . .

# Set environment variables (if needed)
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["python3", "-m", "scanner.scanner"]