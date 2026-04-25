FROM node:22-slim AS builder
WORKDIR /app
COPY package*.json npm-shrinkwrap.json* ./
RUN npm install --production && \
    find node_modules -name "package.json" -exec sed -i 's/"version": "[^"]*"/"version": "0.0.0"/g' {} + && \
    find node_modules -name "CHANGELOG*" -o -name "HISTORY*" -o -name "*.md" | xargs rm -f 2>/dev/null; true

FROM node:22-slim
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY src/ ./src/
COPY public/ ./public/
EXPOSE 3000
CMD ["node", "src/server.js"]
