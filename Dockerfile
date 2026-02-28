# Base node image
FROM node:20-slim AS base
WORKDIR /app

# Install build dependencies for native modules (sqlite3)
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Dependencies stage
FROM base AS dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Final production stage
FROM node:20-slim AS production
WORKDIR /app

# Copy production dependencies
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .

# Create necessary directories
RUN mkdir -p database logs ml_model/model

# Set environment variables
ENV NODE_ENV=production
ENV PORT=5001

# Expose the backend port
EXPOSE 5001

# Start the application
CMD ["node", "backend/server.js"]
