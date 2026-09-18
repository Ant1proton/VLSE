#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
build_dir="${repo_dir}/build-release"
result_dir="${1:-${repo_dir}/results/paired_vs_lse}"
sizes_text="${VLSE_COMPARE_SIZES:-16384 32768 65536 131072 262144}"
rounds="${VLSE_COMPARE_ROUNDS:-3}"
queries="${VLSE_COMPARE_QUERIES:-1000}"
dmax="${VLSE_COMPARE_DMAX:-1}"
quiescence_enabled="${VLSE_REQUIRE_QUIESCENCE:-1}"
quiescence_max_process_cpu="${VLSE_MAX_BACKGROUND_PROCESS_CPU:-25}"
quiescence_samples="${VLSE_QUIESCENCE_SAMPLES:-3}"
quiescence_poll_seconds="${VLSE_QUIESCENCE_POLL_SECONDS:-10}"
quiescence_timeout_seconds="${VLSE_QUIESCENCE_TIMEOUT_SECONDS:-3600}"

if [[ -d "${result_dir}" ]] && [[ -n "$(find "${result_dir}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "Refusing to mix a new experiment with nonempty result directory: ${result_dir}" >&2
  exit 2
fi
mkdir -p "${result_dir}/logs"

cmake -S "${repo_dir}" -B "${build_dir}" -DCMAKE_BUILD_TYPE=Release \
  > "${result_dir}/configure.log" 2>&1
cmake --build "${build_dir}" -j > "${result_dir}/build.log" 2>&1
ctest --test-dir "${build_dir}" \
  -R 'oprf_consistency|paired_collision|vlse_paired_protocol_smoke|lse_protocol_smoke' \
  --output-on-failure > "${result_dir}/ctest.log" 2>&1

environment_file="${result_dir}/environment.txt"
raw_file="${result_dir}/raw_results.txt"
progress_file="${result_dir}/progress.tsv"
manifest_file="${result_dir}/run_manifest.tsv"
snapshot_file="${result_dir}/host_snapshots.log"
actual_cxx="$({ sed -n 's/^CMAKE_CXX_COMPILER:FILEPATH=//p' "${build_dir}/CMakeCache.txt" || true; } | head -n 1)"

{
  date -u '+utc=%Y-%m-%dT%H:%M:%SZ'
  sw_vers
  uname -a
  sysctl -n machdep.cpu.brand_string 2>/dev/null || true
  sysctl -n hw.memsize 2>/dev/null || true
  uptime
  pmset -g therm 2>/dev/null || true
  echo "cmake_cxx_compiler=${actual_cxx}"
  if [[ -n "${actual_cxx}" ]]; then
    "${actual_cxx}" --version | head -n 1
  else
    clang++ --version | head -n 1
  fi
  cmake --version | head -n 1
  echo "oprf_group=ffc3072-q256-shake256-v1"
  echo "oprf_modulus_bits=3072"
  echo "oprf_subgroup_bits=256"
  echo "sizes=${sizes_text}"
  echo "rounds=${rounds}"
  echo "queries=${queries}"
  echo "dmax=${dmax}"
  echo "quiescence_enabled=${quiescence_enabled}"
  echo "quiescence_max_background_process_cpu=${quiescence_max_process_cpu}"
  echo "quiescence_samples=${quiescence_samples}"
  echo "timing_clock=std::chrono::steady_clock"
  echo "keygen_included=0"
  echo "blind_precompute_included_in_online=0"
  echo "dataset_generation_included=0"
  echo "file_io_included=0"
  echo "log_io_included=0"
  echo "network_delay_included=0"
  echo "cache_model=one complete object download per static database/key epoch plus per-keyword OPRF request+response"
  if git -C "${repo_dir}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "git_commit=$(git -C "${repo_dir}" rev-parse HEAD)"
    echo "git_status_begin"
    git -C "${repo_dir}" status --short
    echo "git_status_end"
  fi
  shasum -a 256 "${repo_dir}/common/parameters/ffc3072_q256.pem"
  shasum -a 256 \
    "${build_dir}/benchmarks/lse_protocol_benchmark" \
    "${build_dir}/benchmarks/vlse_protocol_benchmark"
} > "${environment_file}"

find "${repo_dir}/benchmarks" "${repo_dir}/common" "${repo_dir}/paired_vlse" \
  "${repo_dir}/scripts" -type f \
  \( -name '*.cpp' -o -name '*.h' -o -name '*.hpp' -o -name '*.sh' -o -name '*.py' -o -name '*.pem' \) \
  -print0 | sort -z | xargs -0 shasum -a 256 > "${result_dir}/source_manifest.sha256"

: > "${raw_file}"
printf 'utc\tround\tn\tscheme\tstatus\n' > "${progress_file}"
printf 'round\tn\tscheme\tseed\tqueries\tdmax\tlog_file\n' > "${manifest_file}"
: > "${snapshot_file}"

wait_for_quiescence() {
  if [[ "${quiescence_enabled}" != "1" ]]; then
    return
  fi
  local good=0
  local elapsed=0
  local max_cpu
  while (( good < quiescence_samples )); do
    max_cpu="$(ps -Ao pcpu= | awk 'BEGIN { max=0 } { if ($1 > max) max=$1 } END { printf "%.1f", max }')"
    printf '%s\tQUIESCENCE\tmax_process_cpu=%s\tgood=%s/%s\n' \
      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${max_cpu}" "${good}" \
      "${quiescence_samples}" >> "${snapshot_file}"
    if awk -v observed="${max_cpu}" -v limit="${quiescence_max_process_cpu}" \
      'BEGIN { exit !(observed <= limit) }'; then
      good=$((good + 1))
    else
      good=0
    fi
    if (( good >= quiescence_samples )); then
      break
    fi
    if (( elapsed >= quiescence_timeout_seconds )); then
      echo "Host did not become quiescent within ${quiescence_timeout_seconds}s" >&2
      exit 5
    fi
    sleep "${quiescence_poll_seconds}"
    elapsed=$((elapsed + quiescence_poll_seconds))
  done
}

run_one() {
  local scheme="$1"
  local n="$2"
  local round="$3"
  local seed=$((20260917 + round * 1000003 + n * 17))
  local log_file="${result_dir}/logs/round_$(printf '%02d' "${round}")_n_${n}_${scheme}.log"
  wait_for_quiescence
  printf '%s\t%s\t%s\t%s\tSTART\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${round}" "${n}" "${scheme}" \
    | tee -a "${progress_file}"
  printf '%s\t%s\t%s\t%s\n' \
    "${round}" "${n}" "${scheme}" "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $(uptime)" \
    >> "${snapshot_file}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${round}" "${n}" "${scheme}" "${seed}" "${queries}" "${dmax}" \
    "${log_file}" >> "${manifest_file}"
  if [[ "${scheme}" == "LSE" ]]; then
    {
      echo "utc_start=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      echo "command=lse_protocol_benchmark --keywords ${n} --queries ${queries} --dmax ${dmax} --seed ${seed}"
      caffeinate -i "${build_dir}/benchmarks/lse_protocol_benchmark" \
        --keywords "${n}" --queries "${queries}" --dmax "${dmax}" --seed "${seed}"
      echo "utc_end=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    } 2>&1 | tee "${log_file}"
  else
    {
      echo "utc_start=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
      echo "command=vlse_protocol_benchmark --layout paired --keywords ${n} --queries ${queries} --dmax ${dmax} --seed ${seed}"
      caffeinate -i "${build_dir}/benchmarks/vlse_protocol_benchmark" \
        --layout paired --keywords "${n}" --queries "${queries}" \
        --dmax "${dmax}" --seed "${seed}"
      echo "utc_end=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    } 2>&1 | tee "${log_file}"
  fi
  if [[ "$(grep -c '^RESULT ' "${log_file}")" -ne 1 ]]; then
    echo "Expected exactly one RESULT line in ${log_file}" >&2
    exit 3
  fi
  grep '^RESULT ' "${log_file}" >> "${raw_file}"
  printf '%s\t%s\t%s\t%s\tDONE\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${round}" "${n}" "${scheme}" \
    | tee -a "${progress_file}"
}

for n in ${sizes_text}; do
  for round in $(seq 1 "${rounds}"); do
    if (( round % 2 == 1 )); then
      run_one LSE "${n}" "${round}"
      run_one VLSE "${n}" "${round}"
    else
      run_one VLSE "${n}" "${round}"
      run_one LSE "${n}" "${round}"
    fi
  done
done

expected_results=$(( $(wc -w <<< "${sizes_text}") * rounds * 2 ))
actual_results=$(grep -c '^RESULT ' "${raw_file}")
if [[ "${actual_results}" -ne "${expected_results}" ]]; then
  echo "Expected ${expected_results} RESULT lines, found ${actual_results}" >&2
  exit 4
fi
python3 "${repo_dir}/scripts/summarize_paired_vs_lse.py" "${result_dir}"
find "${result_dir}" -type f ! -name 'artifact_manifest.sha256' -print0 \
  | sort -z | xargs -0 shasum -a 256 > "${result_dir}/artifact_manifest.sha256"
