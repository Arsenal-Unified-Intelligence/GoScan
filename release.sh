#!/usr/bin/env bash
# Build the per-platform release zips in precompiled-binaries/.
#
# The version is read from GoScan.go rather than passed in, so the binaries, the
# zip names, and the version every scan report stamps into goscan_version can
# never disagree. Bump `const version` in GoScan.go, then run this.
#
#   ./release.sh
#
set -euo pipefail

cd "$(dirname "$0")"

OUT=precompiled-binaries
LDFLAGS='-s -w'   # strip symbol tables and DWARF; halves the binary

version=$(sed -n 's/^const version = "\(.*\)"$/\1/p' GoScan.go)
if [ -z "$version" ]; then
  echo "error: could not read 'const version' from GoScan.go" >&2
  exit 1
fi
echo "==> Building GoScan v$version"

# Fail before producing artifacts if the source is broken, rather than shipping
# a zip built from code that does not vet.
echo "==> go vet"
go vet ./...

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# platform triples: GOOS GOARCH binary-name
platforms=(
  "linux   amd64 GoScan"
  "windows amd64 GoScan.exe"
  "darwin  amd64 GoScan"
  "darwin  arm64 GoScan"
)

mkdir -p "$OUT"
# Drop zips from previous versions so the directory only ever holds the current
# release; older builds stay reachable through git history and GitHub releases.
rm -f "$OUT"/GoScan-v*.zip

for entry in "${platforms[@]}"; do
  read -r goos goarch binary <<<"$entry"
  stage="$work/$goos-$goarch"
  mkdir -p "$stage"

  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -ldflags="$LDFLAGS" -o "$stage/$binary" .
  cp README.md LICENSE "$stage/"

  zip_name="GoScan-v$version-$goos-$goarch.zip"
  zip_path="$work/$zip_name"   # absolute: the subshell below changes directory
  # -X omits extra file attributes (uid/gid, timestamps) for reproducibility.
  (cd "$stage" && zip -q -X "$zip_path" "$binary" README.md LICENSE)
  mv "$zip_path" "$OUT/$zip_name"
  echo "    $zip_name"
done

echo "==> Checksums"
(cd "$OUT" && sha256sum GoScan-v*.zip > SHA256SUMS && sha256sum -c SHA256SUMS)

# The host build is the only one we can actually execute here; a smoke test
# catches a cross-compile that produced a binary reporting the wrong version.
host_binary="$work/linux-amd64/GoScan"
if [ -x "$host_binary" ] && [ "$(go env GOOS)/$(go env GOARCH)" = "linux/amd64" ]; then
  echo "==> Smoke test"
  reported=$("$host_binary" -h 2>&1 | sed -n '1s/.*v\([0-9.]*\).*/\1/p')
  if [ "$reported" != "$version" ]; then
    echo "error: built binary reports v$reported, expected v$version" >&2
    exit 1
  fi
  echo "    binary reports v$reported"
fi

if ! grep -q "v$version" "$OUT/README.md" 2>/dev/null; then
  echo "warning: $OUT/README.md does not mention v$version — update it before committing" >&2
fi

echo "==> Done. Review and commit $OUT/"
