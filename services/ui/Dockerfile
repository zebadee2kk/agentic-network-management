FROM node:22-alpine AS build
WORKDIR /app
COPY services/ui/package.json ./package.json
RUN npm install --no-audit --no-fund
COPY services/ui/ ./
RUN npm run build

FROM nginx:1.27-alpine
COPY services/ui/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
