# Multi-arch friendly Node base
FROM node:18-alpine

WORKDIR /app

# Install dependencies first (better build caching)
COPY package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev

# Copy the rest of the source
COPY . .

# If your server listens on a different port, change it here and in docker-compose.yml
EXPOSE 8088

# Run via npm to honor your package.json script
CMD ["npm", "start", "--silent"]
