#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${repo_dir}/build-release"
result_dir="${1:-${repo_dir}/results/three_rounds}"
mkdir -p "${result_dir}"

cmake -S "${repo_dir}" -B "${build_dir}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${build_dir}" -j
ctest --test-dir "${build_dir}" --output-on-failure

raw_file="${result_dir}/raw_results.txt"
: > "${raw_file}"

for keywords in 16384 32768 65536 131072 262144; do
  for round in 1 2 3; do
    "${build_dir}/benchmarks/lse_protocol_benchmark" \
      --keywords "${keywords}" --queries 200 --dmax 1 --seed "${round}" \
      | tee -a "${raw_file}"
    "${build_dir}/benchmarks/vlse_protocol_benchmark" \
      --layout paired --keywords "${keywords}" --queries 200 --dmax 1 \
      --seed "${round}" | tee -a "${raw_file}"
  done
done

for dmax in 1 5 10 15 20; do
  for round in 1 2 3; do
    "${build_dir}/benchmarks/lse_protocol_benchmark" \
      --keywords 262144 --queries 200 --dmax "${dmax}" --seed "${round}" \
      | tee -a "${raw_file}"
    "${build_dir}/benchmarks/vlse_protocol_benchmark" \
      --layout paired --keywords 262144 --queries 200 --dmax "${dmax}" \
      --seed "${round}" | tee -a "${raw_file}"
  done
done
