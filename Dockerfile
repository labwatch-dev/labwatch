FROM python:3.12-slim

WORKDIR /app

COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server/ .
COPY agent/install.sh ./install.sh

RUN adduser --disabled-password --gecos "" --uid 1000 labwatch \
    && mkdir -p /app/data /app/dist \
    && chown -R labwatch:labwatch /app

USER labwatch

EXPOSE 8097

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8097"]
