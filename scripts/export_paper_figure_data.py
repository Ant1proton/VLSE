#!/usr/bin/env python3
"""Replace only VLSE/LSE measurements in the legacy-style paper data files.

Zheng et al., Wang et al., protocol labels, and plotting style are untouched.
The main per-keyword communication value is (S + s*c) / s with s=1000.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


N_VALUES = (2**14, 2**15, 2**16, 2**17, 2**18)
QUERY_POINTS = (200, 400, 600, 800, 1000)
EDGE_N_VALUES = (2**14, 2**18)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=Path)
    parser.add_argument("source_figure_data", type=Path)
    parser.add_argument("source_baseline_data", type=Path)
    parser.add_argument("output_figure_data", type=Path)
    parser.add_argument("output_baseline_data", type=Path)
    args = parser.parse_args()

    summaries = read_csv(args.result_dir / "summary.csv")
    communications = read_csv(args.result_dir / "communication_points.csv")
    checkpoints = read_csv(args.result_dir / "query_checkpoints.csv")

    summary_by_key = {
        (row["protocol"], int(row["keywords"])): row for row in summaries
    }
    communication_by_key = {
        (row["protocol"], int(row["keywords"]), int(row["queries"])): row
        for row in communications
    }
    checkpoint_by_key = {
        (row["protocol"], int(row["keywords"]), int(row["queries"])): row
        for row in checkpoints
    }
    for protocol in ("paired_vlse", "LSE"):
        for n in N_VALUES:
            if (protocol, n) not in summary_by_key:
                raise SystemExit(f"missing summary for {protocol}, n={n}")
            if (protocol, n, 1000) not in communication_by_key:
                raise SystemExit(f"missing communication point for {protocol}, n={n}")
        for n in EDGE_N_VALUES:
            for query in QUERY_POINTS:
                if (protocol, n, query) not in checkpoint_by_key:
                    raise SystemExit(
                        f"missing latency checkpoint for {protocol}, n={n}, q={query}"
                    )

    provenance = (
        "2026-09-17 fresh three-process run; shared ffc3072-q256 OPRF; "
        "mean and sample SD; d_max=1"
    )
    communication_provenance = (
        "common cache model: one complete object S per static database/key "
        "epoch plus s OPRF request/response transcripts; plotted value "
        "(S+s*c)/s; binary units"
    )

    # The VLSE input is intentionally standalone.  LSE and the unchanged
    # Zheng/Wang points live in the baseline input, so no superseded LSE row
    # can remain silently present in the file read for the VLSE series.
    figure_rows: list[dict[str, object]] = []
    for n in N_VALUES:
        summary = summary_by_key[("paired_vlse", n)]
        communication = communication_by_key[("paired_vlse", n, 1000)]
        figure_rows.extend(
            [
                {
                    "figure": "setup_runtime",
                    "metric": "setup",
                    "scheme": "VLSE",
                    "n": n,
                    "q": "",
                    "value": float(summary["setup_ms_mean"]) / 1000.0,
                    "sd": float(summary["setup_ms_sample_sd"]) / 1000.0,
                    "unit": "s",
                    "provenance": provenance,
                },
                {
                    "figure": "storage_dbsize_MB",
                    "metric": "storage",
                    "scheme": "VLSE",
                    "n": n,
                    "q": "",
                    "value": summary["serialized_mib"],
                    "sd": 0,
                    "unit": "MiB",
                    "provenance": "complete paired cached object; binary unit",
                },
                {
                    "figure": "perquery_latency",
                    "metric": "perquery_latency",
                    "scheme": "VLSE",
                    "n": n,
                    "q": 1000,
                    "value": summary["online_ms_per_query_mean"],
                    "sd": summary["online_ms_per_query_sample_sd"],
                    "unit": "ms",
                    "provenance": provenance,
                },
                {
                    "figure": "perquery_comm",
                    "metric": "perquery_comm",
                    "scheme": "VLSE",
                    "n": n,
                    "q": 1000,
                    "value": communication["cold_amortized_kib_per_keyword"],
                    "sd": 0,
                    "unit": "KiB",
                    "provenance": communication_provenance,
                },
            ]
        )
    for n, latency_figure, communication_figure in (
        (2**14, "latency_2p14_s", "comm_2p14_MB"),
        (2**18, "latency_2p18_s", "comm_2p18_MB"),
    ):
        for query in QUERY_POINTS:
            checkpoint = checkpoint_by_key[("paired_vlse", n, query)]
            communication = communication_by_key[("paired_vlse", n, query)]
            figure_rows.extend(
                [
                    {
                        "figure": latency_figure,
                        "metric": "batch_latency",
                        "scheme": "VLSE",
                        "n": n,
                        "q": query,
                        "value": checkpoint["batch_latency_s_mean"],
                        "sd": checkpoint["batch_latency_s_sample_sd"],
                        "unit": "s",
                        "provenance": provenance,
                    },
                    {
                        "figure": communication_figure,
                        "metric": "batch_comm",
                        "scheme": "VLSE",
                        "n": n,
                        "q": query,
                        "value": communication["cold_total_mib"],
                        "sd": 0,
                        "unit": "MiB",
                        "provenance": communication_provenance,
                    },
                ]
            )

    baseline_rows = [
        row
        for row in read_csv(args.source_baseline_data)
        if row["scheme"] != "LSE"
    ]
    for n in N_VALUES:
        summary = summary_by_key[("LSE", n)]
        communication = communication_by_key[("LSE", n, 1000)]
        baseline_rows.extend(
            [
                {
                    "metric": "setup",
                    "scheme": "LSE",
                    "n": n,
                    "q": "",
                    "value": float(summary["setup_ms_mean"]) / 1000.0,
                    "unit": "s",
                    "provenance": provenance,
                },
                {
                    "metric": "storage",
                    "scheme": "LSE",
                    "n": n,
                    "q": "",
                    "value": summary["serialized_mib"],
                    "unit": "MiB",
                    "provenance": "complete LSE cached object; binary unit",
                },
                {
                    "metric": "perquery_latency",
                    "scheme": "LSE",
                    "n": n,
                    "q": 1000,
                    "value": summary["online_ms_per_query_mean"],
                    "unit": "ms",
                    "provenance": provenance,
                },
                {
                    "metric": "perquery_comm",
                    "scheme": "LSE",
                    "n": n,
                    "q": 1000,
                    "value": communication["cold_amortized_kib_per_keyword"],
                    "unit": "KiB",
                    "provenance": communication_provenance,
                },
            ]
        )
    for n in EDGE_N_VALUES:
        for query in QUERY_POINTS:
            checkpoint = checkpoint_by_key[("LSE", n, query)]
            communication = communication_by_key[("LSE", n, query)]
            baseline_rows.extend(
                [
                    {
                        "metric": "batch_latency",
                        "scheme": "LSE",
                        "n": n,
                        "q": query,
                        "value": checkpoint["batch_latency_s_mean"],
                        "unit": "s",
                        "provenance": provenance,
                    },
                    {
                        "metric": "batch_comm",
                        "scheme": "LSE",
                        "n": n,
                        "q": query,
                        "value": communication["cold_total_mib"],
                        "unit": "MiB",
                        "provenance": communication_provenance,
                    },
                ]
            )

    write_csv(
        args.output_figure_data,
        ["figure", "metric", "scheme", "n", "q", "value", "sd", "unit", "provenance"],
        figure_rows,
    )
    write_csv(
        args.output_baseline_data,
        ["metric", "scheme", "n", "q", "value", "unit", "provenance"],
        baseline_rows,
    )

    audit_rows: list[dict[str, object]] = []
    for protocol, scheme in (("paired_vlse", "VLSE"), ("LSE", "LSE")):
        for n in N_VALUES:
            summary = summary_by_key[(protocol, n)]
            communication = communication_by_key[(protocol, n, 1000)]
            audit_rows.append(
                {
                    "scheme": scheme,
                    "n": n,
                    "S_bytes": summary["serialized_bytes"],
                    "c_bytes": summary["oprf_wire_bytes_per_query"],
                    "s": 1000,
                    "C_s_bytes": communication["cold_total_bytes"],
                    "Cbar_bytes_per_keyword": communication[
                        "cold_amortized_bytes_per_keyword"
                    ],
                    "first_cold_query_bytes": communication[
                        "first_cold_query_bytes"
                    ],
                    "cached_marginal_bytes": communication[
                        "cached_marginal_bytes_per_keyword"
                    ],
                }
            )
    write_csv(
        args.output_figure_data.parent / "paper_communication_audit.csv",
        [
            "scheme",
            "n",
            "S_bytes",
            "c_bytes",
            "s",
            "C_s_bytes",
            "Cbar_bytes_per_keyword",
            "first_cold_query_bytes",
            "cached_marginal_bytes",
        ],
        audit_rows,
    )


if __name__ == "__main__":
    main()
