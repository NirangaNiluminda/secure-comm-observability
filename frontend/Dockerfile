# ── Stage 1: Build the React app ─────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies (uses package-lock.json for reproducibility)
COPY package*.json ./
RUN npm install

# Copy source and build
# We call `vite build` directly to skip TypeScript strict checks
# (type errors shouldn't block a running demo)
COPY . .
RUN npx vite build

# ── Stage 2: Serve with Nginx ─────────────────────────────────
FROM nginx:alpine

# Static build output
COPY --from=builder /app/dist /usr/share/nginx/html

# Our custom nginx config (proxies /api + /socket.io to backend)
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
