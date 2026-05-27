FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy package into a named sub-directory so relative imports work
COPY . /app/forticnapp_ctf_api/

# One-shot job entrypoint — run as package so relative imports work
ENTRYPOINT ["python", "-m", "forticnapp_ctf_api"]
