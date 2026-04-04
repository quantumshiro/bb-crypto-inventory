"""Benchmark runner for bb-crypto-inventory.

Executes the bbci scanner against the benchmark test servers
and scores results against ground truth.

Usage:
    python -m benchmarks.runner --target http://localhost:9000 --suite phase01
    python -m benchmarks.runner --target http://localhost:9000 --suite phase01 --benchmark BM-09
    python -m benchmarks.runner --target http://localhost:9000 --report results/
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from bbci.agent.orchestrator import AgentOrchestrator
from bbci.config import Config

from benchmarks.scoring import BenchmarkScore, load_ground_truth, score_findings

logger = logging.getLogger("bbci.benchmark")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


async def run_individual_benchmark(
    config: Config,
    base_url: str,
    benchmark_id: str,
    benchmark_def: dict,
) -> dict:
    """Run bbci against a single benchmark endpoint."""
    endpoint = benchmark_def.get("endpoint", "/")
    port = benchmark_def.get("port")
    use_tls = benchmark_def.get("tls", False)

    if port:
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        scheme = "https" if use_tls else parsed.scheme
        target = f"{scheme}://{parsed.hostname}:{port}{endpoint}"
    else:
        target = f"{base_url.rstrip('/')}{endpoint}"

    logger.info(f"Running benchmark {benchmark_id}: {benchmark_def['name']} → {target}")

    orchestrator = AgentOrchestrator(config)
    start = time.monotonic()

    try:
        report = await orchestrator.scan(target)
        duration = time.monotonic() - start

        findings = [
            {
                "id": f.id,
                "category": f.category.value,
                "severity": f.severity.value,
                "algorithm": f.algorithm,
                "key_length": f.key_length,
                "pq_vulnerable": f.pq_vulnerable,
                "confidence": f.confidence,
                "detection_channel": f.detection_channel.value,
                "evidence": f.evidence,
                "endpoint": f.endpoint,
            }
            for f in orchestrator.findings
        ]

        return {
            "benchmark_id": benchmark_id,
            "name": benchmark_def["name"],
            "target": target,
            "duration_seconds": round(duration, 2),
            "findings": findings,
            "finding_count": len(findings),
            "success": True,
        }

    except Exception as e:
        logger.error(f"Benchmark {benchmark_id} failed: {e}")
        return {
            "benchmark_id": benchmark_id,
            "name": benchmark_def["name"],
            "target": target,
            "duration_seconds": time.monotonic() - start,
            "findings": [],
            "finding_count": 0,
            "success": False,
            "error": str(e),
        }


async def run_full_scan(config: Config, base_url: str) -> dict:
    """Run bbci scan against the full target (all endpoints discovered)."""
    logger.info(f"Running full scan against {base_url}")

    orchestrator = AgentOrchestrator(config)
    start = time.monotonic()

    try:
        report = await orchestrator.scan(base_url)
        duration = time.monotonic() - start

        findings = [
            {
                "id": f.id,
                "category": f.category.value,
                "severity": f.severity.value,
                "algorithm": f.algorithm,
                "key_length": f.key_length,
                "pq_vulnerable": f.pq_vulnerable,
                "confidence": f.confidence,
                "detection_channel": f.detection_channel.value,
                "evidence": f.evidence,
                "endpoint": f.endpoint,
            }
            for f in orchestrator.findings
        ]

        return {
            "scan_type": "full",
            "target": base_url,
            "duration_seconds": round(duration, 2),
            "findings": findings,
            "finding_count": len(findings),
            "cbom": json.loads(report.to_json()),
            "success": True,
        }

    except Exception as e:
        logger.error(f"Full scan failed: {e}")
        return {
            "scan_type": "full",
            "target": base_url,
            "findings": [],
            "success": False,
            "error": str(e),
        }


async def run_benchmarks(
    config: Config,
    base_url: str,
    benchmark_filter: str | None = None,
    ground_truth_path: str = "benchmarks/ground_truth.yaml",
    suite: str | None = None,
) -> dict:
    """Run benchmark suite and score results."""
    gt = load_ground_truth(ground_truth_path)
    benchmarks = gt.get("benchmarks", {})
    suite_def: dict | None = None
    negative_control_ids: list[str] | None = None

    if suite:
        suites = gt.get("benchmark_suites", {})
        if suite not in suites:
            raise ValueError(f"Unknown benchmark suite: {suite}")
        suite_def = suites[suite]
        benchmark_ids = set(suite_def.get("benchmark_ids", []))
        benchmarks = {k: v for k, v in benchmarks.items() if k in benchmark_ids}
        negative_control_ids = suite_def.get("negative_control_ids", [])
        suite_phases = suite_def.get("phases")
        if suite_phases:
            config.scan.phases = list(suite_phases)

    if benchmark_filter:
        benchmarks = {
            k: v for k, v in benchmarks.items()
            if k == benchmark_filter or benchmark_filter.lower() in v.get("name", "").lower()
        }

    all_findings: list[dict] = []
    benchmark_results: list[dict] = []

    # Run each benchmark
    for bm_id, bm_def in benchmarks.items():
        result = await run_individual_benchmark(config, base_url, bm_id, bm_def)
        benchmark_results.append(result)
        all_findings.extend(result["findings"])

    # Score against ground truth
    score = score_findings(
        all_findings,
        ground_truth_path,
        benchmark_ids=list(benchmarks.keys()),
        negative_control_ids=negative_control_ids,
    )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": base_url,
        "model": config.agent.model,
        "suite": suite,
        "suite_description": suite_def.get("description") if suite_def else None,
        "phases": config.scan.phases,
        "benchmarks_run": len(benchmark_results),
        "benchmark_results": benchmark_results,
        "scoring": score.summary(),
        "total_findings": len(all_findings),
    }


def print_report(results: dict) -> None:
    """Print a human-readable benchmark report."""
    scoring = results.get("scoring", {})

    print("\n" + "=" * 70)
    print("  BBCI BENCHMARK REPORT")
    print("=" * 70)
    print(f"  Target:     {results.get('target', 'N/A')}")
    print(f"  Model:      {results.get('model', 'N/A')}")
    if results.get("suite"):
        print(f"  Suite:      {results.get('suite')}")
    if results.get("phases") is not None:
        print(f"  Phases:     {results.get('phases')}")
    print(f"  Timestamp:  {results.get('timestamp', 'N/A')}")
    print(f"  Benchmarks: {results.get('benchmarks_run', 0)}")
    print("=" * 70)

    print("\n📊 OVERALL METRICS")
    print(f"  Precision:        {scoring.get('precision', 0):.1%}")
    print(f"  Recall:           {scoring.get('recall', 0):.1%}")
    print(f"  F1 Score:         {scoring.get('f1_score', 0):.1%}")
    print(f"  True Positives:   {scoring.get('true_positives', 0)}")
    print(f"  False Positives:  {scoring.get('false_positives', 0)}")
    print(f"  False Negatives:  {scoring.get('false_negatives', 0)}")
    print(f"  True Negatives:   {scoring.get('true_negatives', 0)}")

    print("\n📋 PER-BENCHMARK RESULTS")
    for bm_id, bm_data in scoring.get("per_benchmark", {}).items():
        detected = bm_data.get("detected", 0)
        expected = bm_data.get("expected", 0)
        status = "✅" if detected >= expected else "❌"
        print(f"  {status} {bm_id}: {bm_data.get('name', '')} — {detected}/{expected} detected")

    print("\n📡 PER-CHANNEL PERFORMANCE")
    for ch, ch_data in scoring.get("per_channel", {}).items():
        detected = ch_data.get("detected", 0)
        expected = ch_data.get("expected", 0)
        pct = (detected / expected * 100) if expected > 0 else 0
        print(f"  {ch}: {detected}/{expected} ({pct:.0f}%)")

    print("\n🎯 CONFIDENCE CALIBRATION")
    for cal in scoring.get("confidence_calibration", []):
        status = "✅" if cal.get("meets_threshold") else "⚠️"
        print(
            f"  {status} {cal.get('benchmark', '')}: "
            f"expected≥{cal.get('expected_min', 0):.1f}, "
            f"actual={cal.get('actual', 0):.2f}"
        )

    print("\n" + "=" * 70)


def main() -> None:
    parser = argparse.ArgumentParser(description="BBCI Benchmark Runner")
    parser.add_argument("--target", required=True, help="Base URL of benchmark server")
    parser.add_argument("--benchmark", default=None, help="Run specific benchmark (e.g., BM-01)")
    parser.add_argument("--suite", default=None, help="Run a benchmark suite (e.g., phase01)")
    parser.add_argument("--ground-truth", default="benchmarks/ground_truth.yaml",
                        help="Path to ground truth YAML")
    parser.add_argument("--report", default=None, help="Directory to save report")
    parser.add_argument("--model", default=None, help="LLM model override")
    parser.add_argument("--config", default=None, help="bbci config file")
    parser.add_argument("--full-scan", action="store_true", help="Run full scan (not individual)")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    # Load config
    config = Config.from_file(args.config) if args.config else Config.load()
    if args.model:
        config.agent.model = args.model

    if args.full_scan:
        results = asyncio.run(run_full_scan(config, args.target))
    else:
        results = asyncio.run(run_benchmarks(
            config, args.target, args.benchmark, args.ground_truth, args.suite
        ))

    # Print report
    print_report(results)

    # Save report
    if args.report:
        report_dir = Path(args.report)
        report_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = report_dir / f"benchmark_{ts}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))
        print(f"\n📁 Report saved to {report_path}")


if __name__ == "__main__":
    main()
