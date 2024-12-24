FROM node:20 AS build-env

WORKDIR /app/

COPY package.json yarn.lock /app/
RUN yarn install

COPY ./ /app/
RUN yarn build

FROM gcr.io/distroless/nodejs20-debian11
WORKDIR /app/

COPY --from=build-env /app/node_modules /app/node_modules
COPY --from=build-env /app/dist /app/dist

CMD ["./dist/main.js"]
