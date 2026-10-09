#!/usr/bin/env python3
"""
scripts/split_datasets.py

Standardized, Stratified Train/Test Dataset Splitter for Faraday Laya Guard.
Follows global machine learning evaluation standards:
1. 4-Way Balanced 2K Test Set (50/50 Malicious vs Benign, 50/50 Static vs Semantic):
   - 500 Static Malicious (Proportionally sampled across threat domains & sources)
   - 500 Semantic Malicious (Proportionally sampled across threat domains & sources)
   - 500 Static Benign (Proportionally sampled across filesystem, bash, db, and read-only search tools)
   - 500 Semantic Benign (Proportionally sampled across emails, transfers, messaging, calendar, bookings)
2. Comprehensive Disjoint Training Set:
   - All remaining records from master_benchmark.parquet form the training set.
   - Guaranteed zero data leakage: Test ∩ Train = ∅.
3. Fully deterministic via fixed random seed (default: 42).
"""

import argparse
from collections import Counter, defaultdict
from pathlib import Path
import random
from typing import Any, Callable

import pyarrow as pa
import pyarrow.parquet as pq
from rich.console import Console
from rich.table import Table

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MASTER_PARQUET = PROCESSED_DIR / "master_benchmark.parquet"

BENCHMARK_SCHEMA = pa.schema([
    ("id", pa.string()),
    ("source_dataset", pa.string()),
    ("traffic_direction", pa.string()),
    ("threat_domain", pa.string()),
    ("analysis_tier", pa.string()),      # STATIC_CAPABLE | SEMANTIC_REQUIRED | HYBRID
    ("cwe", pa.string()),
    ("owasp_llm", pa.string()),
    ("tool_name", pa.string()),
    ("tool_arguments", pa.string()),  # JSON serialized string
    ("context", pa.string()),
    ("is_malicious", pa.bool_()),
])

# Deterministic tool classification for benign controls
STATIC_BENIGN_TOOLS = {
    # File & Filesystem Operations
    "execute_bash", "read_filesystem", "query_analytics_db",
    "search_files_by_filename", "create_file", "get_file_by_id",
    "search_files", "append_to_file", "delete_file", "read_file",
    "list_files", "share_file",
    # Read-only Structured Lookups & Queries
    "get_rating_reviews_for_restaurants", "get_price_for_restaurants",
    "get_cuisine_type_for_restaurants", "get_hotels_prices",
    "get_rating_reviews_for_hotels", "get_restaurants_address",
    "get_car_price_per_day", "get_rating_reviews_for_car_rental",
    "check_restaurant_opening_hours", "get_hotels_address",
    "get_all_hotels_in_city", "get_car_types_available",
    "get_car_fuel_options", "get_all_car_rental_companies_in_city",
    "get_car_rental_address", "get_all_restaurants_in_city",
    "get_flight_information", "get_contact_information_for_restaurants",
    "get_dietary_restrictions_for_all_restaurants",
}


def stratified_proportional_sample(
    records: list[dict[str, Any]],
    target_count: int,
    key_func: Callable[[dict[str, Any]], Any],
    seed: int = 42,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Performs stratified proportional sampling across subcategories.
    Guarantees every subcategory gets at least 1 sample if available,
    while maintaining exact proportional representation and target count.
    """
    random.seed(seed)
    groups = defaultdict(list)
    for r in records:
        groups[key_func(r)].append(r)

    total_pool = len(records)
    allocated: dict[Any, int] = {}

    # Initial proportional allocation
    for k, grp in sorted(groups.items(), key=lambda x: len(x[1])):
        prop = len(grp) / total_pool
        count = max(1, round(prop * target_count))
        count = min(count, len(grp))
        allocated[k] = count

    # Adjust rounding differences to match exact target_count
    curr_total = sum(allocated.values())
    diff = target_count - curr_total

    sorted_keys = sorted(groups.keys(), key=lambda k: len(groups[k]), reverse=(diff > 0))
    idx = 0
    max_loops = len(sorted_keys) * 10
    while diff != 0 and idx < max_loops:
        k = sorted_keys[idx % len(sorted_keys)]
        if diff > 0 and allocated[k] < len(groups[k]):
            allocated[k] += 1
            diff -= 1
        elif diff < 0 and allocated[k] > 1:
            allocated[k] -= 1
            diff += 1
        idx += 1

    sampled: list[dict[str, Any]] = []
    remaining: list[dict[str, Any]] = []

    for k, grp in groups.items():
        shuffled = list(grp)
        random.shuffle(shuffled)
        k_count = allocated[k]
        sampled.extend(shuffled[:k_count])
        remaining.extend(shuffled[k_count:])

    random.shuffle(sampled)
    random.shuffle(remaining)
    return sampled, remaining


def generate_splits(test_size: int = 2000, seed: int = 42):
    """Generates 4-way balanced test set and disjoint train set."""
    if not MASTER_PARQUET.exists():
        console.print(f"[bold red]❌ Master parquet not found at {MASTER_PARQUET}[/bold red]")
        return

    table = pq.read_table(MASTER_PARQUET)
    raw_records = table.to_pylist()
    console.print(f"[bold cyan]📦 Loaded {len(raw_records)} records from master benchmark pool.[/bold cyan]")

    target_per_bucket = test_size // 4
    if test_size % 4 != 0:
        raise ValueError("test_size must be divisible by 4 for equal 4-way balance.")

    buckets: dict[str, list[dict[str, Any]]] = {
        "STATIC_MALICIOUS": [],
        "SEMANTIC_MALICIOUS": [],
        "STATIC_BENIGN": [],
        "SEMANTIC_BENIGN": [],
    }

    # Normalize analysis_tier and sort into buckets
    for r in raw_records:
        is_mal = r["is_malicious"]
        tier = r["analysis_tier"]
        tool = r["tool_name"]

        if is_mal:
            if tier == "STATIC_CAPABLE":
                buckets["STATIC_MALICIOUS"].append(r)
            else:
                buckets["SEMANTIC_MALICIOUS"].append(r)
        else:
            if tool in STATIC_BENIGN_TOOLS:
                r["analysis_tier"] = "STATIC_CAPABLE"
                buckets["STATIC_BENIGN"].append(r)
            else:
                r["analysis_tier"] = "SEMANTIC_REQUIRED"
                buckets["SEMANTIC_BENIGN"].append(r)

    console.print("\n[bold]📊 Available Pool by 4-Way Category:[/bold]")
    for b_name, b_items in buckets.items():
        console.print(f"  • {b_name:<20}: [bold green]{len(b_items)}[/bold green] records")

    test_records: list[dict[str, Any]] = []
    train_records: list[dict[str, Any]] = []

    # 1. Static Malicious Stratification: by threat_domain & source_dataset
    sm_test, sm_train = stratified_proportional_sample(
        buckets["STATIC_MALICIOUS"],
        target_per_bucket,
        lambda x: (x["threat_domain"], x["source_dataset"]),
        seed=seed,
    )
    test_records.extend(sm_test)
    train_records.extend(sm_train)

    # 2. Semantic Malicious Stratification: by threat_domain & source_dataset
    sem_test, sem_train = stratified_proportional_sample(
        buckets["SEMANTIC_MALICIOUS"],
        target_per_bucket,
        lambda x: (x["threat_domain"], x["source_dataset"]),
        seed=seed,
    )
    test_records.extend(sem_test)
    train_records.extend(sem_train)

    # 3. Static Benign Stratification: by tool_name & source_dataset
    sb_test, sb_train = stratified_proportional_sample(
        buckets["STATIC_BENIGN"],
        target_per_bucket,
        lambda x: (x["tool_name"], x["source_dataset"]),
        seed=seed,
    )
    test_records.extend(sb_test)
    train_records.extend(sb_train)

    # 4. Semantic Benign Stratification: by tool_name & source_dataset
    semb_test, semb_train = stratified_proportional_sample(
        buckets["SEMANTIC_BENIGN"],
        target_per_bucket,
        lambda x: (x["tool_name"], x["source_dataset"]),
        seed=seed,
    )
    test_records.extend(semb_test)
    train_records.extend(semb_train)

    # Verification: Zero Data Leakage
    test_ids = {r["id"] for r in test_records}
    train_ids = {r["id"] for r in train_records}
    intersection = test_ids.intersection(train_ids)
    assert len(intersection) == 0, f"DATA LEAKAGE DETECTED! Overlapping IDs: {intersection}"
    assert len(test_records) == test_size, f"Test size mismatch: {len(test_records)} vs {test_size}"
    assert len(test_records) + len(train_records) == len(raw_records), "Total count conservation failed."

    # Shuffle final sets
    random.seed(seed)
    random.shuffle(test_records)
    random.shuffle(train_records)

    # Save Parquet files
    test_out = PROCESSED_DIR / "smoke_test_2k.parquet"
    train_out = PROCESSED_DIR / "benchmark_train.parquet"

    table_test = pa.Table.from_pylist(test_records, schema=BENCHMARK_SCHEMA)
    pq.write_table(table_test, test_out, compression="snappy")

    table_train = pa.Table.from_pylist(train_records, schema=BENCHMARK_SCHEMA)
    pq.write_table(table_train, train_out, compression="snappy")

    console.print(f"\n[bold green]✅ Test Set ({len(test_records)} records) written to:[/bold green]")
    console.print(f"   • {test_out}")
    console.print(f"   • {test_canonical}")
    console.print(f"[bold green]✅ Train Set ({len(train_records)} records) written to:[/bold green]")
    console.print(f"   • {train_out}")

    # Display Test Set Distribution Table
    display_summary(test_records, "4-Way Balanced Test Set (2,000 Records)")
    display_summary(train_records, "Disjoint Training Set (Remaining Records)")


def display_summary(records: list[dict[str, Any]], title: str):
    t = Table(title=title)
    t.add_column("Tier", style="blue")
    t.add_column("Verdict", style="yellow")
    t.add_column("Domain / Category", style="cyan")
    t.add_column("Count", style="green")

    grouped = Counter((r["analysis_tier"], "MALICIOUS" if r["is_malicious"] else "BENIGN", r["threat_domain"]) for r in records)
    for (tier, mal_str, domain), cnt in sorted(grouped.items()):
        t.add_row(tier, mal_str, domain, str(cnt))

    console.print(t)


def main():
    parser = argparse.ArgumentParser(description="Stratified 4-Way Train/Test Splitter.")
    parser.add_argument("--test-size", type=int, default=2000, help="Test set size (default: 2000, 4x500).")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility.")
    args = parser.parse_args()

    generate_splits(test_size=args.test_size, seed=args.seed)


if __name__ == "__main__":
    main()
