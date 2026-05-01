# ============================================================
# Cayde-6 Frontend - Multi-stage Docker build
# ============================================================

# --- Stage 1: Install dependencies ---
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* .npmrc* ./
RUN npm install --legacy-peer-deps --ignore-scripts

# --- Stage 2: Build the Next.js application ---
FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build-time env vars (overridable via docker build --build-arg)
ARG NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
ARG NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_WS_URL=$NEXT_PUBLIC_WS_URL
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

# --- Stage 3: Production runner ---
FROM node:20-alpine AS runner

LABEL maintainer="Wilab <admin@somoswilab.com>"
LABEL description="Cayde-6 Autonomous Defense Platform - Dashboard"
LABEL version="1.0.0"

WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy built assets - standalone output mode
COPY --from=builder /app/public ./public 2>/dev/null || true
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000 || exit 1

CMD ["node", "server.js"]
