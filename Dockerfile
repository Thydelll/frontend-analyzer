# Imagem para deploy (Railway, Fly, VPS...). Instala o Chromium com as libs de sistema.
FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    HOST=0.0.0.0 \
    TRUST_PROXY=1

WORKDIR /app

# Dependências primeiro (melhor cache de camadas)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
 && npx playwright install --with-deps chromium \
 && chmod -R a+rX /ms-playwright \
 && rm -rf /var/lib/apt/lists/*

COPY . .

# Roda sem root
USER node

EXPOSE 3000
CMD ["node", "server.js"]
