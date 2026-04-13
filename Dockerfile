# Stage 1: Build Go agent binaries
FROM golang:1.25-alpine AS agent-builder

WORKDIR /build
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" -trimpath -o /out/labwatch-linux-amd64 ./cmd/labwatch/ \
 && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
    -ldflags="-s -w" -trimpath -o /out/labwatch-linux-arm64 ./cmd/labwatch/ \
 && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build \
    -ldflags="-s -w" -trimpath -o /out/labwatch-linux-armv7 ./cmd/labwatch/

# Stage 2: Python server
FROM python:3.12-slim

WORKDIR /app

RUN adduser --disabled-password --gecos "" --uid 1000 labwatch \
    && mkdir -p /app/data /app/dist \
    && chown -R labwatch:labwatch /app

COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=labwatch:labwatch server/ .
COPY --chown=labwatch:labwatch agent/install.sh ./install.sh
COPY --from=agent-builder --chown=labwatch:labwatch /out/labwatch-* ./dist/

USER labwatch

EXPOSE 8097

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8097/api/v1/health')" || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8097"]
