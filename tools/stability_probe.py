"""Bounded HTTP load/stability gate for a deployed ServiceOps instance."""
import argparse
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


def one_request(url, timeout):
    started = time.monotonic()
    try:
        response = requests.get(url, timeout=timeout)
        return response.status_code, (time.monotonic() - started) * 1000
    except requests.RequestException:
        return 0, (time.monotonic() - started) * 1000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:80/health")
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--max-error-rate", type=float, default=0.001)
    parser.add_argument("--max-p95-ms", type=float, default=500)
    args = parser.parse_args()
    if not 1 <= args.requests <= 100000 or not 1 <= args.concurrency <= 500:
        parser.error("requests must be 1-100000 and concurrency 1-500")
    started = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [executor.submit(one_request, args.url, args.timeout) for _ in range(args.requests)]
        for future in as_completed(futures):
            results.append(future.result())
    latencies = sorted(duration for _, duration in results)
    errors = sum(status < 200 or status >= 400 for status, _ in results)
    p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))]
    duration = time.monotonic() - started
    evidence = {
        "url": args.url, "requests": len(results), "concurrency": args.concurrency,
        "errors": errors, "error_rate": errors / len(results),
        "p50_ms": round(statistics.median(latencies), 2), "p95_ms": round(p95, 2),
        "max_ms": round(max(latencies), 2), "throughput_rps": round(len(results) / duration, 2),
        "passed": errors / len(results) <= args.max_error_rate and p95 <= args.max_p95_ms,
    }
    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
