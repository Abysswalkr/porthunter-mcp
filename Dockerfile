# Imagen ligera para ejecutar PortHunter MCP (stdio)
FROM python:3.12-slim

WORKDIR /app

# Instala sistema mínimo para compilar dependencias si fuera necesario
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates build-essential \
 && rm -rf /var/lib/apt/lists/*

# Copia pyproject y el paquete
COPY pyproject.toml ./
COPY server/porthunter_mcp ./server/porthunter_mcp

# Instalar el paquete
RUN pip install --no-cache-dir .

# Variables por defecto (puedes override en docker run)
ENV PORT_HUNTER_REQUIRE_TOKEN=true \
    PORT_HUNTER_MAX_PCAP_MB=200 \
    PORT_HUNTER_ALLOW_PRIVATE=false \
    PORT_HUNTER_CACHE_DIR=.cache/porthunter

# Directorio de capturas (montable)
VOLUME ["/captures"]
ENV PORT_HUNTER_ALLOWED_DIR=/captures

# Comando por defecto: stdio server
CMD ["python", "-m", "porthunter.server"]
