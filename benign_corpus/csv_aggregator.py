"""Read CSV, compute simple aggregates. No network, no eval, no subprocess."""
import csv
from collections import defaultdict
from pathlib import Path


def aggregate_by_category(path: Path) -> dict[str, float]:
    totals: dict[str, float] = defaultdict(float)
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                amount = float(row["amount"])
            except (KeyError, ValueError):
                continue
            totals[row.get("category", "uncategorized")] += amount
    return dict(totals)


if __name__ == "__main__":
    import sys
    result = aggregate_by_category(Path(sys.argv[1]))
    for cat, total in sorted(result.items()):
        print(f"{cat}: {total:.2f}")
