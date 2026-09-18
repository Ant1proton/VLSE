#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${repo_dir}/build-release"

cmake -S "${repo_dir}" -B "${build_dir}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${build_dir}" -j
ctest --test-dir "${build_dir}" --output-on-failure

"${build_dir}/benchmarks/lse_protocol_benchmark" \
  --keywords 4096 --queries 40 --dmax 1 --seed 1
"${build_dir}/benchmarks/vlse_protocol_benchmark" \
  --layout original --keywords 4096 --queries 40 --dmax 1 --seed 1
"${build_dir}/benchmarks/vlse_protocol_benchmark" \
  --layout paired --keywords 4096 --queries 40 --dmax 1 --seed 1
