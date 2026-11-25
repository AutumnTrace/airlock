#!/usr/bin/env bash
# Cross-compile release archives into dist/. Usage: scripts/build-release.sh v0.1.0
set -euo pipefail

tag="${1:?usage: build-release.sh <tag>}"
version="${tag#v}"
out=dist
rm -rf "$out"
mkdir -p "$out"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os="${target%/*}"
  arch="${target#*/}"
  name="airlock_${version}_${os}_${arch}"
  ext=""
  [ "$os" = windows ] && ext=".exe"
  mkdir -p "$out/$name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=${version}" \
    -o "$out/$name/airlock$ext" ./cmd/airlock
  cp LICENSE README.md "$out/$name/"
  if [ "$os" = windows ]; then
    (cd "$out" && zip -qr "$name.zip" "$name")
  else
    tar -C "$out" -czf "$out/$name.tar.gz" "$name"
  fi
  rm -rf "${out:?}/$name"
done

(cd "$out" && sha256sum -- * > checksums.txt)
ls -l "$out"
