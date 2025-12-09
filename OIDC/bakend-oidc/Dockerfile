FROM golang:1.22 AS builder
WORKDIR /app

COPY go.mod .
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN go build -o server .

FROM scratch
WORKDIR /root/
COPY --from=builder /app/server .

EXPOSE 80
CMD ["./server"]
