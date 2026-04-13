FROM python:3.12-slim

WORKDIR /app

RUN adduser --disabled-password --gecos "" --uid 1000 labwatch \
    && mkdir -p /app/data /app/dist \
    && chown -R labwatch:labwatch /app

COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=labwatch:labwatch server/ .
COPY --chown=labwatch:labwatch agent/install.sh ./install.sh

USER labwatch

EXPOSE 8097

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8097/api/v1/health')" || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8097", "--workers", "2"]
