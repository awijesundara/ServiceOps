"""Report offline catalog coverage against an inspected message inventory.

This checks translation entries only; it does not claim that inventory review,
source integration, linguistic review or browser acceptance have completed.
"""
import argparse
import json
import logging
from pathlib import Path
import sys
from string import Formatter

logger = logging.getLogger(__name__)


def parameter_names(message):
    try:
        names = set()
        for _, name, specification, conversion in Formatter().parse(message):
            if name is None:
                continue
            if not name.isidentifier() or specification or conversion:
                raise ValueError("Only simple named translation parameters are supported")
            names.add(name)
        return names
    except (ValueError, TypeError):
        logger.exception("Invalid catalog parameter syntax")
        raise


def coverage(inventory_path, catalog_path, language=None):
    try:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        catalogs = json.loads(catalog_path.read_text(encoding="utf-8"))
        if inventory.get("errors"):
            raise ValueError("Inventory has source-reading errors")
        rows = inventory.get("messages")
        if not isinstance(rows, list) or not isinstance(catalogs, dict) or not catalogs:
            raise ValueError("Inventory and catalogs must contain message data")
        required = set()
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("message"), str) or not row["message"].strip():
                raise ValueError("Invalid inventory message")
            required.add(row["message"])
        if not required:
            raise ValueError("An empty inventory cannot prove complete coverage")
        if language is not None and language not in catalogs:
            raise ValueError(f"Unknown language: {language}")
        codes = [language] if language is not None else sorted(catalogs)
        result = []
        for code in codes:
            entry = catalogs[code]
            messages = entry.get("messages") if isinstance(entry, dict) else None
            if not isinstance(messages, dict):
                raise ValueError(f"Invalid message catalog: {code}")
            missing = sorted(required - {key for key, value in messages.items() if isinstance(value, str) and value.strip()})
            invalid_parameters = []
            for message in sorted(required - set(missing)):
                try:
                    if parameter_names(message) != parameter_names(messages[message]):
                        invalid_parameters.append(message)
                except (ValueError, TypeError):
                    invalid_parameters.append(message)
            translated = len(required) - len(missing)
            result.append({"language": code, "required": len(required), "present": translated, "missing": missing,
                           "invalid_parameters": invalid_parameters,
                           "coverage_percent": round(translated * 100 / len(required), 3),
                           "complete": not missing and not invalid_parameters})
        return result
    except (OSError, UnicodeError, ValueError, TypeError, KeyError):
        logger.exception("Could not calculate offline translation coverage")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--catalogs", type=Path, default=Path(__file__).resolve().parents[1] / "serviceops_core/locales/catalogs.json")
    parser.add_argument("--language")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    try:
        result = coverage(args.inventory, args.catalogs, args.language)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps([{key: value for key, value in row.items() if key != "missing"} for row in result], sort_keys=True))
        return 1 if args.require_complete and any(not row["complete"] for row in result) else 0
    except (OSError, UnicodeError, ValueError, TypeError, KeyError):
        logger.error("Offline translation coverage gate failed")
        return 2


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
