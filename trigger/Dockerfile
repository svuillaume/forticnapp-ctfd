FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install trigger + dynamic bridge dependencies
COPY trigger/requirements.txt ./trigger-requirements.txt
COPY forticnapp_ctf_api/requirements.txt ./dynamic-requirements.txt
RUN pip install --no-cache-dir -r trigger-requirements.txt -r dynamic-requirements.txt

# ── Static bridge (in-process) ─────────────────────────────────────────────
COPY static_ctf/ctfd.py       ./ctfd.py
COPY static_ctf/ctfbuilder.py ./ctfbuilder.py
COPY static_ctf/build.py      ./build.py
COPY static_ctf/fortinet.css  ./fortinet.css
COPY static_ctf/home.html     ./home.html
COPY static_ctf/ctf/          ./ctf/

# ── Dynamic bridge (subprocess) ────────────────────────────────────────────
COPY forticnapp_ctf_api/ ./dynamic/

# ── Trigger app ────────────────────────────────────────────────────────────
COPY trigger/app.py ./app.py

ENV STATIC_SCHEMA_DIR=/app/ctf
ENV TRIGGER_PORT=5555

EXPOSE 5555

CMD ["python", "app.py"]
