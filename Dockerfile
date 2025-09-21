FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

ENV PORT_HUNTER_REQUIRE_TOKEN=true \
    PORT_HUNTER_MAX_PCAP_MB=50

# STDIO es el modo normal; si algún día expones HTTP, cambia el CMD.
CMD ["python", "-m", "porthunter.server"]
