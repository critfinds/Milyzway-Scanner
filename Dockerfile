FROM python:3.11-slim

# System deps for some libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/vulnscanner

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1 \
    TZ=UTC

CMD ["python", "-m", "scanner.app", "--targets", "examples/targets.txt"]
