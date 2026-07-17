# Build
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -o /out/dpf-sim-controller ./cmd

# Run (distroless: this is dev tooling but keep it small)
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /out/dpf-sim-controller .
USER 65532:65532
ENTRYPOINT ["/dpf-sim-controller"]
