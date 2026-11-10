FROM node:22.22.3-bookworm-slim

WORKDIR /app

ENV npm_config_update_notifier=false \
    npm_config_fund=false \
    npm_config_audit=false

COPY package.json package-lock.json ./
# npm can exit after a completed install with "Exit handler never called".
RUN npm ci --no-audit --no-fund \
    || test -s node_modules/next/package.json \
    || npm ci --no-audit --no-fund

COPY . .

ARG NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

RUN npm run build

EXPOSE 3000

CMD ["npm", "start"]
