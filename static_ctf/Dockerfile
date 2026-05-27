FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy builder modules
COPY ctfd.py ctfbuilder.py build.py ./

# Copy static challenge schema
COPY ctf/ ./ctf/

# Bundle theme CSS + home page (pushed to CTFd on every run)
COPY fortinet.css home.html ./

ENV STATIC_SCHEMA_DIR=/app/ctf

ENTRYPOINT ["python", "build.py", "--build"]
