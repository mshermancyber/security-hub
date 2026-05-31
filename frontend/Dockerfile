FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --silent
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
RUN apk add --no-cache openssl
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY docker-entrypoint.sh /docker-entrypoint.d/40-sechub-tls.sh
COPY --from=build /app/dist /usr/share/nginx/html
RUN chmod +x /docker-entrypoint.d/40-sechub-tls.sh
EXPOSE 80 443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD wget -q -O- http://127.0.0.1/healthz || exit 1
