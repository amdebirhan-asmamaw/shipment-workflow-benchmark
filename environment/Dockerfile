FROM node:22.14.0-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    NODE_PATH=/usr/local/lib/node_modules

RUN groupmod -n agent node \
    && usermod -l agent -d /home/agent -m node \
    && npm install -g typescript@5.7.3 @types/node@22.13.4 \
    && npm cache clean --force \
    && mkdir -p /app/shipment-wal /logs/agent /logs/verifier

WORKDIR /app/shipment-wal
COPY workspace/ /app/shipment-wal/

RUN sed -i 's/\r$//' /app/shipment-wal/build_and_test.sh \
    && chmod +x /app/shipment-wal/build_and_test.sh \
    && tsc -p /app/shipment-wal/tsconfig.json \
    && chown -R agent:agent /app /home/agent

