# pulsar's image, as `make conformance` runs it: a static binary on a
# distroless base, with no shell and no package manager.
#
# Base images are pinned by tag and digest: the tag says which release, the
# digest is what is pulled. They are bumped by hand, with a changelog entry in
# docs/harness.md. The Go release must be the one go.mod names, which
# make dockerfile-check enforces.

FROM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS build
WORKDIR /src
# Modules first, so that a change to the source reuses the cached download.
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /pulsar ./cmd/pulsar

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /pulsar /pulsar
ENTRYPOINT ["/pulsar"]
