# Base image for Node
FROM node:20-alpine AS base

LABEL maintainer="https://github.com/prowler-cloud"
WORKDIR /app

# Install dependencies only when needed
RUN apk add --no-cache libc6-compat

# Copy package.json and lock files to install dependencies
COPY package.json yarn.lock* package-lock.json* pnpm-lock.yaml* ./
RUN if [ -f package-lock.json ]; then npm install; else echo "Lockfile not found." && exit 1; fi

# Copy the rest of the application code
COPY . .

# Development stage
FROM base AS dev
CMD ["npm", "run", "dev"]

# Production stage
FROM base AS prod
RUN npm run build
CMD ["npm", "start"]
