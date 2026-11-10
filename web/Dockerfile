FROM node:22.22.3-bookworm-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm --version && npm ci

COPY . .

ARG NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

RUN npm run build

EXPOSE 3000

CMD ["npm", "start"]
