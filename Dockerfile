# Build the manager binary
FROM golang:1.17 as builder
ARG GOPROXY=https://proxy.golang.org

RUN wget http://pr-art.europe.stater.corp/artifactory/auto-local/certs/pr-root.cer -O - | sed -e "s/\r//g" > /usr/local/share/ca-certificates/pr-root.crt \
 && update-ca-certificates

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download -x

# Copy the go source
COPY *.go .

# Build
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -a -o webhook .

FROM distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/webhook /bin/webhook

# Run as UID for nobody
USER 65532:65532

ENTRYPOINT ["/bin/webhook"]
