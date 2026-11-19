FROM ghcr.io/xtls/xray-core:26.11.9 AS xray
FROM node:22-bookworm-slim
ENV NODE_ENV=production DATA_DIR=/data XRAY_LOCATION_ASSET=/usr/local/share/xray
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=xray /usr/local/share/xray/ /usr/local/share/xray/
COPY server.js ./
COPY public ./public
EXPOSE 3000
CMD ["node", "server.js"]
