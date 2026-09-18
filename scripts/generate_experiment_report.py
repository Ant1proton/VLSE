#!/usr/bin/env python3
"""Generate a Chinese audit report and old/new comparison from final CSVs."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def fmt(value: float, digits: int = 3) -> str:
    return f"{value:.{digits}f}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=Path)
    parser.add_argument("--old-vlse", type=Path)
    parser.add_argument("--old-baselines", type=Path)
    args = parser.parse_args()

    result_dir = args.result_dir.resolve()
    summary = read_csv(result_dir / "summary.csv")
    communication = read_csv(result_dir / "communication_points.csv")
    summary_by_key = {
        (row["protocol"], int(row["keywords"])): row for row in summary
    }
    communication_by_key = {
        (row["protocol"], int(row["keywords"]), int(row["queries"])): row
        for row in communication
    }
    sizes = sorted({int(row["keywords"]) for row in summary})

    lines = [
        "# LSE/VLSE 最新端到端实验审计报告",
        "",
        "## 统计口径",
        "",
        "- LSE 与 VLSE 在同一个静态数据库/密钥 epoch 内各下载并缓存一次完整对象。",
        "- 对 `s` 个关键词，累计通信为 `C(s)=S+s*c`，主图每关键词值为 `S/s+c`。",
        "- `S`、`S+c`、`c`、`S+s*c` 和 `S/s+c` 均保留在 `communication_points.csv`。",
        "- Setup 包含 genuine 构造、索引构造/插入和 dummy 填充；密钥生成、blind 预生成、数据生成、文件/日志 I/O、网络延迟不计入。",
        "- 每个规模三个独立进程；均值与离散量分别为算术均值和样本标准差。",
        "",
        "## 端到端汇总",
        "",
        "| 协议 | n | Setup (s) | genuine (s) | insert (ms) | dummy (ms) | dummy 槽 | S (MiB) | 在线 (ms/关键词) | c (bytes) | S/1000+c (KiB/关键词) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for protocol, display in (("paired_vlse", "VLSE"), ("LSE", "LSE")):
        for n in sizes:
            row = summary_by_key[(protocol, n)]
            comm = communication_by_key[(protocol, n, 1000)]
            lines.append(
                "| {display} | {n} | {setup} ± {setup_sd} | {genuine} | "
                "{insert} | {dummy} | {dummies} | {storage} | {online} ± "
                "{online_sd} | {wire} | {amortized} |".format(
                    display=display,
                    n=n,
                    setup=fmt(float(row["setup_ms_mean"]) / 1000),
                    setup_sd=fmt(float(row["setup_ms_sample_sd"]) / 1000),
                    genuine=fmt(float(row["setup_genuine_ms_mean"]) / 1000),
                    insert=fmt(float(row["setup_insert_ms_mean"])),
                    dummy=fmt(float(row["setup_dummy_ms_mean"])),
                    dummies=int(float(row["dummy_records"])),
                    storage=fmt(float(row["serialized_mib"])),
                    online=fmt(float(row["online_ms_per_query_mean"])),
                    online_sd=fmt(float(row["online_ms_per_query_sample_sd"])),
                    wire=int(row["oprf_wire_bytes_per_query"]),
                    amortized=fmt(
                        float(comm["cold_amortized_kib_per_keyword"])
                    ),
                )
            )

    lines.extend(
        [
            "",
            "## 同规模相对值",
            "",
            "| n | LSE/VLSE Setup | LSE/VLSE 在线耗时 | LSE/VLSE 对象 |",
            "|---:|---:|---:|---:|",
        ]
    )
    for n in sizes:
        vlse = summary_by_key[("paired_vlse", n)]
        lse = summary_by_key[("LSE", n)]
        lines.append(
            f"| {n} | {float(lse['setup_ms_mean']) / float(vlse['setup_ms_mean']):.3f}x "
            f"| {float(lse['online_ms_per_query_mean']) / float(vlse['online_ms_per_query_mean']):.3f}x "
            f"| {float(lse['serialized_bytes']) / float(vlse['serialized_bytes']):.3f}x |"
        )

    lines.extend(
        [
            "",
            "## 完整性检查",
            "",
            "汇总器在写表前逐行验证：`S+s*c` 恒等式、首次冷查询和缓存边际值、`genuine+dummy=capacity`、dummy component 数、查询全部成功、Setup 分段闭合，以及所有排除项标志均为 0。任一条件失败都会终止，不生成论文表。",
            "",
            "每个进程的完整 stdout/stderr 位于 `logs/`；`run_manifest.tsv` 保存命令与 seed；`environment.txt` 保存机器、编译器、参数和二进制哈希；`source_manifest.sha256` 与 `artifact_manifest.sha256` 用于复核源码和交付文件。",
        ]
    )

    (result_dir / "EXPERIMENT_REPORT_ZH.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )

    if args.old_vlse is None or args.old_baselines is None:
        return

    old_vlse = read_csv(args.old_vlse)
    old_baselines = read_csv(args.old_baselines)
    old_index: dict[tuple[str, int, str], float] = {}
    for row in old_vlse + old_baselines:
        if row["scheme"] not in ("VLSE", "LSE"):
            continue
        if row["metric"] not in (
            "setup",
            "storage",
            "perquery_latency",
            "perquery_comm",
        ):
            continue
        old_index[(row["scheme"], int(row["n"]), row["metric"])] = float(
            row["value"]
        )

    comparison: list[dict[str, object]] = []
    for protocol, scheme in (("paired_vlse", "VLSE"), ("LSE", "LSE")):
        for n in sizes:
            row = summary_by_key[(protocol, n)]
            comm = communication_by_key[(protocol, n, 1000)]
            new_values = {
                "setup": float(row["setup_ms_mean"]) / 1000.0,
                "storage": float(row["serialized_mib"]),
                "perquery_latency": float(row["online_ms_per_query_mean"]),
                "perquery_comm": float(comm["cold_amortized_kib_per_keyword"]),
            }
            for metric, new_value in new_values.items():
                old_value = old_index[(scheme, n, metric)]
                comparison.append(
                    {
                        "scheme": scheme,
                        "n": n,
                        "metric": metric,
                        "old_value": old_value,
                        "new_value": new_value,
                        "absolute_change": new_value - old_value,
                        "new_over_old": new_value / old_value,
                        "interpretation": (
                            "new common 3072/256-bit OPRF and complete rerun; "
                            "not a same-binary machine-noise comparison"
                        ),
                    }
                )
    with (result_dir / "old_vs_new.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(comparison[0]))
        writer.writeheader()
        writer.writerows(comparison)


if __name__ == "__main__":
    main()
