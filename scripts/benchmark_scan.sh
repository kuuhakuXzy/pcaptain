#!/usr/bin/env bash
set -euo pipefail

PCAP_DIR="${1:-/mnt/d/New folder/pcaptain/benchmark_pcaps}"
REPO="/mnt/d/New folder/pcaptain"
FASTSCAN_BIN="${REPO}/fast_scan/build/fastscan"

if ! command -v tshark >/dev/null 2>&1; then
  echo "Installing tshark..."
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tshark wireshark-common >/dev/null
fi

if [[ ! -x "$FASTSCAN_BIN" ]]; then
  echo "Building fastscan..."
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cmake g++ libpcap-dev pkg-config make >/dev/null
  rm -rf "${REPO}/fast_scan/build"
  mkdir -p "${REPO}/fast_scan/build"
  (cd "${REPO}/fast_scan/build" && cmake .. && make -j"$(nproc)")
fi

run_tshark() {
  local f="$1"
  tshark -r "$f" -T fields -e frame.protocols >/dev/null
}

run_fastscan() {
  local f="$1"
  shift
  "$FASTSCAN_BIN" "$@" "$f" >/dev/null
}

echo "=== PCAP benchmark (FIRST-2015 samples) ==="
echo "fastscan: $FASTSCAN_BIN"
echo "tshark:   $(command -v tshark)"
echo

shopt -s nullglob
files=("$PCAP_DIR"/*.pcap)
if ((${#files[@]} == 0)); then
  echo "No .pcap files in $PCAP_DIR" >&2
  exit 1
fi

printf "%-45s %10s %12s %12s %8s\n" "file" "size_MB" "tshark_s" "fastscan_s" "speedup"
printf "%-45s %10s %12s %12s %8s\n" "----" "-------" "--------" "----------" "-------"

for f in "${files[@]}"; do
  base=$(basename "$f")
  size_mb=$(awk -v s="$(stat -c%s "$f")" 'BEGIN{printf "%.1f", s/1024/1024}')

  start=$(date +%s.%N)
  if run_tshark "$f"; then ts_ok=1; else ts_ok=0; fi
  end=$(date +%s.%N)
  tshark_s=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.2f", b-a}')

  start=$(date +%s.%N)
  if run_fastscan "$f" --summary --fingerprint; then fs_ok=1; else fs_ok=0; fi
  end=$(date +%s.%N)
  fast_s=$(awk -v a="$start" -v b="$end" 'BEGIN{printf "%.2f", b-a}')

  speedup=$(awk -v t="$tshark_s" -v f="$fast_s" 'BEGIN{if (f>0) printf "%.1fx", t/f; else print "n/a"}')

  status=""
  [[ $ts_ok -eq 1 && $fs_ok -eq 1 ]] || status=" (ERR)"
  printf "%-45s %10s %12s %12s %8s%s\n" "$base" "$size_mb" "$tshark_s" "$fast_s" "$speedup" "$status"

  echo "--- fastscan output (first line) for $base ---"
  "$FASTSCAN_BIN" --summary --fingerprint "$f" 2>/dev/null | head -2 || true
  echo
done

echo "=== Done ==="
