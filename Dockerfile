FROM golang:1.14-alpine AS build
LABEL maintainer="Mauro Rappa <maurorappa@aol.co.uk>"
WORKDIR /go/src/apifx
COPY . /go/src/apifx
RUN CGO_ENABLED=0 go build -o apifx apifx.go && chmod +x apifx
RUN CGO_ENABLED=0 go build -o mockapi mock_api.go && chmod +x mockapi

FROM nginx:alpine
COPY --from=build /go/src/apifx/apifx /bin/apifx
COPY --from=build /go/src/apifx/mockapi /bin/mockapi
RUN apk add --no-cache supervisor
RUN adduser -S -G nobody noone
RUN mkdir /etc/nginx/html && echo Ciao > /etc/nginx/html/index.html
COPY supervisord.conf /etc/supervisord.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY swagger.json /tmp/swagger.json
ENTRYPOINT ["supervisord", "-c", "/etc/supervisord.conf", "-d", "/home/noone"]
