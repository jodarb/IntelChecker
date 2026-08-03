FROM node:20-alpine AS build

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ .
# public/logo.png is a symlink to the repo-root logo.png for local dev; that target
# only exists in this build context if the deployer kept the file. Drop the symlink
# and copy the real file back in if present — logo.pn[g] is a glob, so a missing
# file matches nothing and the COPY is a no-op instead of failing the build.
RUN rm -f ./public/logo.png
COPY logo.pn[g] ./public/
# Same optional-copy trick for weights.json: glob matches the file if present at
# the repo root, matches nothing (no build failure) if the deployer left it untouched.
RUN rm -f ./public/weights.json
COPY weights.jso[n] ./public/
RUN npm run build

FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
