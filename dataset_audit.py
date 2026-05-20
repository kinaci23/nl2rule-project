import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


SUSPICIOUS_PATTERNS = {
    "port_list_comma": re.compile(r"->\s+\S+\s+\d+,\d+"),
    "flags_plus": re.compile(r"flags:[^;]*\+"),
    "raw_limit_keyword": re.compile(r"\blimit:\s*"),
    "chat_artifact": re.compile(r"<\|.*?\|>"),
}


def load_rows(path: Path):
    rows = []
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            payload = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            rows.append({"line_no": line_no, "error": f"invalid_json: {exc}"})
            continue

        messages = payload.get("messages")
        if not isinstance(messages, list) or len(messages) != 2:
            rows.append({"line_no": line_no, "error": "expected_two_messages"})
            continue

        user_text = messages[0].get("content", "")
        assistant_text = messages[1].get("content", "")
        rows.append(
            {
                "line_no": line_no,
                "user": user_text,
                "assistant": assistant_text,
            }
        )
    return rows


def classify_prompt(text: str) -> str:
    lowered = text.lower()
    mapping = [
        ("sql", "SQL Injection"),
        ("xss", "XSS"),
        ("cross-site", "XSS"),
        ("brute", "Brute Force"),
        ("path", "Path Traversal"),
        ("dizin", "Path Traversal"),
        ("c2", "Malware C2"),
        ("keşif", "Recon"),
        ("tarama", "Recon"),
        ("rce", "RCE"),
        ("uzak kod", "RCE"),
        ("ddos", "DDoS/DoS"),
        ("dos", "DDoS/DoS"),
    ]
    for needle, label in mapping:
        if needle in lowered:
            return label
    return "Unknown"


def audit_rows(rows):
    stats = Counter()
    categories = Counter()
    flagged_examples = defaultdict(list)

    for row in rows:
        if "error" in row:
            stats[row["error"]] += 1
            flagged_examples[row["error"]].append(row)
            continue

        assistant = row["assistant"].strip()
        user_text = row["user"]
        categories[classify_prompt(user_text)] += 1

        stats["valid_rows"] += 1
        if assistant.startswith("alert "):
            stats["starts_with_alert"] += 1
        else:
            flagged_examples["not_alert"].append(row)

        if "sid:" in assistant:
            stats["has_sid"] += 1
        else:
            flagged_examples["missing_sid"].append(row)

        if "rev:" in assistant:
            stats["has_rev"] += 1
        else:
            flagged_examples["missing_rev"].append(row)

        if assistant.count("(") == assistant.count(")"):
            stats["balanced_parentheses"] += 1
        else:
            flagged_examples["unbalanced_parentheses"].append(row)

        for name, pattern in SUSPICIOUS_PATTERNS.items():
            if pattern.search(assistant):
                stats[name] += 1
                flagged_examples[name].append(row)

    return stats, categories, flagged_examples


def print_examples(title: str, rows, limit: int):
    if not rows:
        return
    print(f"\n[{title}]")
    for row in rows[:limit]:
        if "error" in row:
            print(f"- line {row['line_no']}: {row['error']}")
            continue
        print(f"- line {row['line_no']}")
        print(f"  user: {row['user']}")
        print(f"  rule: {row['assistant']}")


def main():
    parser = argparse.ArgumentParser(description="Audit Snort fine-tuning data quality.")
    parser.add_argument("--data", default="data/train.jsonl", help="Path to training jsonl file")
    parser.add_argument("--examples", type=int, default=3, help="How many flagged samples to print")
    args = parser.parse_args()

    path = Path(args.data)
    if not path.exists():
        raise SystemExit(f"Data file not found: {path}")

    rows = load_rows(path)
    stats, categories, flagged = audit_rows(rows)

    total_rows = len([row for row in rows if "error" not in row])
    print(f"dataset: {path}")
    print(f"rows: {total_rows}")
    print(f"starts_with_alert: {stats['starts_with_alert']}/{total_rows}")
    print(f"has_sid: {stats['has_sid']}/{total_rows}")
    print(f"has_rev: {stats['has_rev']}/{total_rows}")
    print(f"balanced_parentheses: {stats['balanced_parentheses']}/{total_rows}")

    for key in ("port_list_comma", "flags_plus", "raw_limit_keyword", "chat_artifact"):
        print(f"{key}: {stats[key]}")

    print("\ncategories:")
    for category, count in categories.most_common():
        print(f"- {category}: {count}")

    for key in (
        "missing_rev",
        "unbalanced_parentheses",
        "port_list_comma",
        "flags_plus",
        "raw_limit_keyword",
        "chat_artifact",
        "not_alert",
    ):
        print_examples(key, flagged[key], args.examples)


if __name__ == "__main__":
    main()
