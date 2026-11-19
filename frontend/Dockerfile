FROM node:20-alpine AS build

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ .
# public/logo is a symlink to the repo-root logo/ folder for local dev; that target
# only exists in this build context if the deployer kept the files. Drop the symlink
# and copy the real files back in if present — light.pn[g]/dark.pn[g] are globs, so
# a missing file matches nothing and the COPY is a no-op instead of failing the build.
RUN rm -rf ./public/logo && mkdir -p ./public/logo
COPY logo/light.pn[g] ./public/logo/
COPY logo/dark.pn[g] ./public/logo/
RUN npm run build

FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
