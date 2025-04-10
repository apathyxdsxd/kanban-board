FROM node:17.2-alpine3.12
WORKDIR /app

# add `/app/node_modules/.bin` to $PATH
ENV PATH /app/node_modules/.bin:$PATH

# install and cache app dependencies
COPY package.json /app/package.json
RUN npm install

# add app
COPY . /app

# start app # default port is 4200
CMD ng serve --host 0.0.0.0

