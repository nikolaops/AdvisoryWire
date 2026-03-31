FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src

RUN npm run build

FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY --from=builder /app/dist ./dist
COPY src/persistence/migrations/*.sql ./dist/persistence/migrations/

ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "dist/app/index.js"]
