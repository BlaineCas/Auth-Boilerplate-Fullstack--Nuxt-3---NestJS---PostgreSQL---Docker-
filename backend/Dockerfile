FROM node:24-alpine AS base
LABEL version="1.0.0"
LABEL description="Base image for Boilerplate NestJS backend."

WORKDIR /usr/src/app
COPY package*.json ./
FROM base AS prod-deps
LABEL description="Installs production dependencies for Boilerplate."
RUN npm ci --only=production --ignore-scripts
FROM base AS dev-deps
LABEL description="Installs all (including development) dependencies for Boilerplate."
RUN npm install --ignore-scripts --no-audit --no-fund

FROM dev-deps AS builder
LABEL description="Builds the Boilerplate NestJS application from TypeScript to JavaScript."
WORKDIR /usr/src/app
COPY . .
RUN npm run build

FROM node:24-alpine AS production
LABEL description="Production-ready image for Boilerplate NestJS backend."
ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

WORKDIR /usr/src/app

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=prod-deps /usr/src/app/node_modules ./node_modules
COPY package*.json ./
COPY --from=builder /usr/src/app/dist ./dist

USER appuser

EXPOSE ${PORT:-3000}

CMD ["node", "dist/main.js"]

FROM dev-deps AS development
LABEL description="Development image for Boilerplate NestJS backend with hot-reloading."
WORKDIR /usr/src/app
COPY . .

EXPOSE ${PORT:-3000}

CMD ["npm", "run", "start:dev"]
