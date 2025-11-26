FROM node:20-alpine AS base
WORKDIR /app

# Instala dependencias y construye el proyecto
FROM base AS build
RUN corepack enable
COPY package.json ./
RUN pnpm install
COPY . .
RUN pnpm build
# Conserva solo dependencias de producción
RUN pnpm prune --prod

# Imagen final ligera
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json .
EXPOSE 3000
CMD ["node", "dist/src/main.js"]
