FROM python:3.12-slim

WORKDIR /app

# Install git for cloning repos during scans
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ /app/backend/
COPY scanner/ /app/scanner/

ENV PYTHONPATH=/app

CMD celery -A backend.tasks.scan_tasks worker --loglevel=info & uvicorn backend.main:app --host 0.0.0.0 --port 8000
