#!/usr/bin/env python3
"""Summarize the paired-VLSE/LSE benchmark without third-party packages."""

from __future__ import annotations

import argparse
import csv
import statistics
from pathlib import Path

QUERY_CHECKPOINTS = (200, 400, 600, 800, 1000)

NUMERIC_FIELDS = {
    "modulus_bits": int,
    "subgroup_bits": int,
    "seed": int,
    "keywords": int,
    "queries": int,
    "dmax": int,
    "setup_ms": float,
    "setup_initialization_ms": float,
    "setup_genuine_ms": float,
    "setup_insert_ms": float,
    "setup_dummy_ms": float,
    "blind_precompute_ms": float,
    "tgen_ms": float,
    "search_decrypt_ms": float,
    "online_ms": float,
    "serialized_bytes": int,
    "cache_object_bytes": int,
    "communication_bytes": int,
    "cold_total_bytes": int,
    "cold_amortized_bytes_per_keyword": float,
    "first_cold_query_bytes": int,
    "warm_marginal_bytes_per_keyword": int,
    "oprf_evaluations_per_query": int,
    "oprf_wire_bytes_per_query": int,
    "genuine_records": int,
    "dummy_records": int,
    "dummy_components": int,
    "capacity_slots": int,
    "setup_attempts": int,
    "failed_setup_attempts": int,
    "successful_inserts": int,
    "failed_inserts": int,
    "eviction_steps": int,
    "rollback_count": int,
    "maximum_eviction_chain": int,
    "relocation_steps": int,
    "maximum_relocation_chain": int,
    "query_successes": int,
    "candidate_records_total": int,
    "candidate_records_max": int,
    "decrypt_component_attempts": int,
    "keygen_included": int,
    "blind_precompute_included_in_online": int,
    "dataset_generation_included": int,
    "file_io_included": int,
    "log_io_included": int,
    "network_delay_included": int,
    **{f"online_ms_q{query}": float for query in QUERY_CHECKPOINTS},
}


def parse_result(line: str) -> dict[str, object]:
    fields: dict[str, object] = {}
    for item in line.strip().split()[1:]:
        key, value = item.split("=", 1)
        converter = NUMERIC_FIELDS.get(key, str)
        fields[key] = converter(value)
    return fields


def mean(rows: list[dict[str, object]], field: str) -> float:
    return statistics.fmean(float(row[field]) for row in rows)


def sample_sd(rows: list[dict[str, object]], field: str) -> float:
    values = [float(row[field]) for row in rows]
    return statistics.stdev(values) if len(values) > 1 else 0.0


def validate_row(row: dict[str, object]) -> None:
    protocol = str(row["protocol"])
    queries = int(row["queries"])
    object_bytes = int(row["cache_object_bytes"])
    wire_bytes = int(row["oprf_wire_bytes_per_query"])
    expected_total = object_bytes + queries * wire_bytes
    if int(row["serialized_bytes"]) != object_bytes:
        raise SystemExit(f"{protocol}: serialized/cache-object byte mismatch")
    if int(row["communication_bytes"]) != expected_total:
        raise SystemExit(f"{protocol}: communication is not S + s*c")
    if int(row["cold_total_bytes"]) != expected_total:
        raise SystemExit(f"{protocol}: cold-total byte mismatch")
    if int(row["first_cold_query_bytes"]) != object_bytes + wire_bytes:
        raise SystemExit(f"{protocol}: first-cold-query byte mismatch")
    if int(row["warm_marginal_bytes_per_keyword"]) != wire_bytes:
        raise SystemExit(f"{protocol}: warm marginal is not c")
    if int(row["genuine_records"]) + int(row["dummy_records"]) != int(
        row["capacity_slots"]
    ):
        raise SystemExit(f"{protocol}: genuine + dummy does not equal capacity")
    if int(row["dummy_components"]) != int(row["dummy_records"]) * int(
        row["dmax"]
    ):
        raise SystemExit(f"{protocol}: dummy-component count mismatch")
    if int(row["query_successes"]) != queries:
        raise SystemExit(f"{protocol}: not every query succeeded")
    for excluded in (
        "keygen_included",
        "blind_precompute_included_in_online",
        "dataset_generation_included",
        "file_io_included",
        "log_io_included",
        "network_delay_included",
    ):
        if int(row[excluded]) != 0:
            raise SystemExit(f"{protocol}: unexpected timing flag {excluded}=1")
    phase_sum = (
        float(row["setup_initialization_ms"])
        + float(row["setup_genuine_ms"])
        + float(row["setup_insert_ms"])
        + float(row["setup_dummy_ms"])
    )
    if abs(phase_sum - float(row["setup_ms"])) > 0.01:
        raise SystemExit(
            f"{protocol}: Setup phases do not partition setup_ms "
            f"({phase_sum} vs {row['setup_ms']})"
        )
    for checkpoint in QUERY_CHECKPOINTS:
        value = float(row[f"online_ms_q{checkpoint}"])
        if queries >= checkpoint and value < 0:
            raise SystemExit(f"{protocol}: missing query checkpoint {checkpoint}")
        if queries < checkpoint and value >= 0:
            raise SystemExit(f"{protocol}: unexpected query checkpoint {checkpoint}")
    if queries == 1000 and abs(
        float(row["online_ms_q1000"]) - float(row["online_ms"])
    ) > 0.01:
        raise SystemExit(f"{protocol}: q=1000 checkpoint does not equal online_ms")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=Path)
    parser.add_argument(
        "--query-points",
        default="200,400,600,800,1000",
        help="comma-separated query counts for cold-communication accounting",
    )
    args = parser.parse_args()

    result_dir = args.result_dir.resolve()
    raw_path = result_dir / "raw_results.txt"
    rows = [
        parse_result(line)
        for line in raw_path.read_text(encoding="utf-8").splitlines()
        if line.startswith("RESULT ")
    ]
    if not rows:
        raise SystemExit(f"no RESULT lines found in {raw_path}")

    parameter_profiles = {
        (
            str(row["backend"]),
            str(row["group"]),
            int(row["modulus_bits"]),
            int(row["subgroup_bits"]),
        )
        for row in rows
    }
    if len(parameter_profiles) != 1:
        raise SystemExit(
            "raw_results.txt mixes incompatible OPRF parameter profiles: "
            f"{sorted(parameter_profiles)}"
        )

    counters: dict[tuple[str, int], int] = {}
    for row in rows:
        validate_row(row)
        key = (str(row["protocol"]), int(row["keywords"]))
        counters[key] = counters.get(key, 0) + 1
        row["round"] = counters[key]
        queries = int(row["queries"])
        row["tgen_ms_per_query"] = float(row["tgen_ms"]) / queries
        row["search_decrypt_ms_per_query"] = (
            float(row["search_decrypt_ms"]) / queries
        )
        row["online_ms_per_query"] = float(row["online_ms"]) / queries
        row["cold_kib_per_query"] = (
            int(row["communication_bytes"]) / 1024.0 / queries
        )

    raw_fields = [
        "protocol",
        "round",
        "backend",
        "group",
        "modulus_bits",
        "subgroup_bits",
        "seed",
        "keywords",
        "queries",
        "dmax",
        "setup_ms",
        "setup_initialization_ms",
        "setup_genuine_ms",
        "setup_insert_ms",
        "setup_dummy_ms",
        "blind_precompute_ms",
        "tgen_ms",
        "search_decrypt_ms",
        "online_ms",
        "tgen_ms_per_query",
        "search_decrypt_ms_per_query",
        "online_ms_per_query",
        "serialized_bytes",
        "cache_object_bytes",
        "communication_bytes",
        "cold_total_bytes",
        "cold_amortized_bytes_per_keyword",
        "first_cold_query_bytes",
        "warm_marginal_bytes_per_keyword",
        "cold_kib_per_query",
        "oprf_evaluations_per_query",
        "oprf_wire_bytes_per_query",
        "genuine_records",
        "dummy_records",
        "dummy_components",
        "capacity_slots",
        "setup_attempts",
        "failed_setup_attempts",
        "successful_inserts",
        "failed_inserts",
        "eviction_steps",
        "rollback_count",
        "maximum_eviction_chain",
        "relocation_steps",
        "maximum_relocation_chain",
        "query_successes",
        "candidate_records_total",
        "candidate_records_max",
        "decrypt_component_attempts",
        "keygen_included",
        "blind_precompute_included_in_online",
        "dataset_generation_included",
        "file_io_included",
        "log_io_included",
        "network_delay_included",
        *[f"online_ms_q{query}" for query in QUERY_CHECKPOINTS],
    ]
    with (result_dir / "raw_results.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=raw_fields)
        writer.writeheader()
        writer.writerows(rows)

    groups: dict[tuple[str, int, int, int], list[dict[str, object]]] = {}
    for row in rows:
        key = (
            str(row["protocol"]),
            int(row["keywords"]),
            int(row["queries"]),
            int(row["dmax"]),
        )
        groups.setdefault(key, []).append(row)

    summary_rows: list[dict[str, object]] = []
    for (protocol, keywords, queries, dmax), group in sorted(groups.items()):
        summary_rows.append(
            {
                "protocol": protocol,
                "backend": str(group[0]["backend"]),
                "group": str(group[0]["group"]),
                "modulus_bits": int(group[0]["modulus_bits"]),
                "subgroup_bits": int(group[0]["subgroup_bits"]),
                "keywords": keywords,
                "queries": queries,
                "dmax": dmax,
                "samples": len(group),
                "setup_ms_mean": mean(group, "setup_ms"),
                "setup_ms_sample_sd": sample_sd(group, "setup_ms"),
                "setup_initialization_ms_mean": mean(
                    group, "setup_initialization_ms"
                ),
                "setup_initialization_ms_sample_sd": sample_sd(
                    group, "setup_initialization_ms"
                ),
                "setup_genuine_ms_mean": mean(group, "setup_genuine_ms"),
                "setup_genuine_ms_sample_sd": sample_sd(
                    group, "setup_genuine_ms"
                ),
                "setup_insert_ms_mean": mean(group, "setup_insert_ms"),
                "setup_insert_ms_sample_sd": sample_sd(group, "setup_insert_ms"),
                "setup_dummy_ms_mean": mean(group, "setup_dummy_ms"),
                "setup_dummy_ms_sample_sd": sample_sd(group, "setup_dummy_ms"),
                "blind_precompute_ms_mean": mean(group, "blind_precompute_ms"),
                "blind_precompute_ms_sample_sd": sample_sd(group, "blind_precompute_ms"),
                "tgen_ms_per_query_mean": mean(group, "tgen_ms_per_query"),
                "tgen_ms_per_query_sample_sd": sample_sd(group, "tgen_ms_per_query"),
                "search_decrypt_ms_per_query_mean": mean(
                    group, "search_decrypt_ms_per_query"
                ),
                "search_decrypt_ms_per_query_sample_sd": sample_sd(
                    group, "search_decrypt_ms_per_query"
                ),
                "online_ms_per_query_mean": mean(group, "online_ms_per_query"),
                "online_ms_per_query_sample_sd": sample_sd(
                    group, "online_ms_per_query"
                ),
                "serialized_bytes": int(group[0]["serialized_bytes"]),
                "serialized_mib": int(group[0]["serialized_bytes"]) / 2**20,
                "oprf_wire_bytes_per_query": int(
                    group[0]["oprf_wire_bytes_per_query"]
                ),
                "cold_communication_bytes": int(group[0]["communication_bytes"]),
                "cold_kib_per_query": mean(group, "cold_kib_per_query"),
                "first_cold_query_bytes": int(group[0]["first_cold_query_bytes"]),
                "warm_marginal_bytes_per_keyword": int(
                    group[0]["warm_marginal_bytes_per_keyword"]
                ),
                "genuine_records": int(group[0]["genuine_records"]),
                "dummy_records": int(group[0]["dummy_records"]),
                "dummy_components": int(group[0]["dummy_components"]),
                "capacity_slots": int(group[0]["capacity_slots"]),
                "setup_attempts_mean": mean(group, "setup_attempts"),
                "failed_setup_attempts_mean": mean(
                    group, "failed_setup_attempts"
                ),
                "successful_inserts_mean": mean(group, "successful_inserts"),
                "failed_inserts_mean": mean(group, "failed_inserts"),
                "eviction_steps_mean": mean(group, "eviction_steps"),
                "rollback_count_mean": mean(group, "rollback_count"),
                "maximum_eviction_chain_max": max(
                    int(row["maximum_eviction_chain"]) for row in group
                ),
                "relocation_steps_mean": mean(group, "relocation_steps"),
                "maximum_relocation_chain_max": max(
                    int(row["maximum_relocation_chain"]) for row in group
                ),
                "query_successes": int(group[0]["query_successes"]),
                "candidate_records_total_mean": mean(
                    group, "candidate_records_total"
                ),
                "candidate_records_max": max(
                    int(row["candidate_records_max"]) for row in group
                ),
                "decrypt_component_attempts_mean": mean(
                    group, "decrypt_component_attempts"
                ),
            }
        )

    summary_fields = list(summary_rows[0])
    with (result_dir / "summary.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=summary_fields)
        writer.writeheader()
        writer.writerows(summary_rows)

    query_points = [int(value) for value in args.query_points.split(",")]
    communication_rows: list[dict[str, object]] = []
    for summary in summary_rows:
        for query_count in query_points:
            object_bytes = int(summary["serialized_bytes"])
            wire_bytes = int(summary["oprf_wire_bytes_per_query"])
            total_bytes = object_bytes + query_count * wire_bytes
            communication_rows.append(
                {
                    "protocol": summary["protocol"],
                    "group": summary["group"],
                    "modulus_bits": summary["modulus_bits"],
                    "subgroup_bits": summary["subgroup_bits"],
                    "keywords": summary["keywords"],
                    "queries": query_count,
                    "cache_model": "one object download per static database/key epoch",
                    "first_download_bytes": object_bytes,
                    "first_download_mib": object_bytes / 2**20,
                    "object_bytes": object_bytes,
                    "oprf_wire_bytes_per_query": wire_bytes,
                    "first_cold_query_bytes": object_bytes + wire_bytes,
                    "first_cold_query_mib": (object_bytes + wire_bytes) / 2**20,
                    "cold_total_bytes": total_bytes,
                    "cold_total_mib": total_bytes / 2**20,
                    "cold_amortized_bytes_per_keyword": total_bytes / query_count,
                    "cold_amortized_kib_per_keyword": total_bytes
                    / 1024.0
                    / query_count,
                    "cold_kib_per_query": total_bytes / 1024.0 / query_count,
                    "warm_total_bytes": query_count * wire_bytes,
                    "cached_marginal_bytes_per_keyword": wire_bytes,
                    "warm_kib_per_query": wire_bytes / 1024.0,
                }
            )
    communication_fields = list(communication_rows[0])
    with (result_dir / "communication_points.csv").open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=communication_fields)
        writer.writeheader()
        writer.writerows(communication_rows)

    checkpoint_rows: list[dict[str, object]] = []
    for (protocol, keywords, queries, dmax), group in sorted(groups.items()):
        for checkpoint in QUERY_CHECKPOINTS:
            if checkpoint > queries:
                continue
            field = f"online_ms_q{checkpoint}"
            checkpoint_rows.append(
                {
                    "protocol": protocol,
                    "group": str(group[0]["group"]),
                    "modulus_bits": int(group[0]["modulus_bits"]),
                    "subgroup_bits": int(group[0]["subgroup_bits"]),
                    "keywords": keywords,
                    "queries": checkpoint,
                    "dmax": dmax,
                    "samples": len(group),
                    "online_ms_mean": mean(group, field),
                    "online_ms_sample_sd": sample_sd(group, field),
                    "batch_latency_s_mean": mean(group, field) / 1000.0,
                    "batch_latency_s_sample_sd": sample_sd(group, field)
                    / 1000.0,
                }
            )
    if checkpoint_rows:
        with (result_dir / "query_checkpoints.csv").open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(file, fieldnames=list(checkpoint_rows[0]))
            writer.writeheader()
            writer.writerows(checkpoint_rows)


if __name__ == "__main__":
    main()
