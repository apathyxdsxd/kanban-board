FROM node:18.20.2-alpine

WORKDIR /app
COPY package.json .

RUN npm install -g npm@8.19.4 && \
    npm install --legacy-peer-deps --force

COPY . .
RUN npm run build -- --configuration=production

CMD ["npm", "start", "--", "--host", "0.0.0.0"]