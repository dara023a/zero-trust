#!/usr/bin/env bash
# Menjalankan ketiga layanan sekaligus (Termux/Linux). Ctrl+C menghentikan semua.
cd "$(dirname "$0")/.." || exit 1
mkdir -p logs
pids=()
trap 'kill "${pids[@]}" 2>/dev/null; exit 0' INT TERM
node transkrip/index.js >logs/transkrip.log 2>&1 & pids+=($!)
node nilai/index.js     >logs/nilai.log     2>&1 & pids+=($!)
sleep 1
node gateway/index.js   >logs/gateway.log   2>&1 & pids+=($!)
echo "Gateway :3000 | Nilai :3001 | Transkrip :3002  (log di folder logs/)"
echo "Tekan Ctrl+C untuk berhenti."
wait
