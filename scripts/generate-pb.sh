#!/usr/bin/env bash

SRC="$1"
DST="$2"

# check_arg - Ensures that all arguments are present
function check_arg() {
  if [ "$#" -ne 2 ]; then
    echo "Usage: generate-pb.sh [src] [dest]"
    echo "You probably want this (you may need to use absolute paths): ./generate-pb.sh credstack/proto credstack/pkg/models"
    exit 1
  fi
}

# check_pkg - Ensures that all required packages are installed with the host
function check_pkg() {
  declare -A required_bins=(
    [protoc]="protoc"
    [protoc-gen-go]="protoc-gen-go"
    [protoc-go-inject-tag]="protoc-go-inject-tag (https://github.com/stevezaluk/protoc-go-inject-tag)"
  )

  for bin in "${!required_bins[@]}"; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      echo "[err] Missing package: ${required_bins[$bin]}"
    fi
  done
}

# generate - Generates the protobuf's and inject's tags
function generate() {
  echo "[info] Generating protos to: $DST"
  protoc -I "$SRC" --go_out "$DST" --go_opt=paths=source_relative $SRC/*/*.proto

  echo "[info] Injecting tags to: $DST"
  protoc-go-inject-tag inject -i "$DST"
}

check_arg "$@"
check_pkg
generate