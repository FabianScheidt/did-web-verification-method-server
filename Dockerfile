FROM node:20 AS build-env

WORKDIR /app/

COPY package.json package-lock.json /app/
RUN npm install

COPY ./ /app/
RUN npm run build

FROM gcr.io/distroless/nodejs20-debian11
WORKDIR /app/

COPY --from=build-env /app/node_modules /app/node_modules
COPY --from=build-env /app/dist /app/dist

CMD ["./dist/main.js"]
