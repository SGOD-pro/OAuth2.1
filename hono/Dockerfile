# Multi-stage production build for SWYRA Auth Hono Backend
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build:node

# Production image
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV UV_THREADPOOL_SIZE=16

# Copy production artifacts
COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist/index.js ./dist/index.js

EXPOSE 3000

CMD ["node", "dist/index.js"]
