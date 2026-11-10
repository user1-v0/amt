FROM node:22.22.3-bookworm-slim

WORKDIR /app

ENV npm_config_update_notifier=false \
    npm_config_fund=false \
    npm_config_audit=false

# Node 22.22.3 ships npm 10.9.8, which crashes during npm ci on some machines.
RUN npm install -g npm@10.8.2

COPY package.json package-lock.json ./
RUN npm --version && npm ci --no-audit --no-fund

COPY . .

ARG NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

RUN npm run build

EXPOSE 3000

CMD ["npm", "start"]
