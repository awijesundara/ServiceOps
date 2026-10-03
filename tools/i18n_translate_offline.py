"""Machine-translate the source messages offline with MADLAD-400.

Build-time only: requires `ctranslate2` and `sentencepiece` (not application
dependencies) and a CTranslate2 conversion of google/madlad400-3b-mt
(Apache-2.0). Runs entirely on this machine; nothing is sent anywhere.

Output is a JSON-lines file of {"language", "source", "translation"} records,
appended as each batch finishes so an interrupted run resumes where it stopped.
Feed the result to tools/i18n_build_catalogs.py catalogs, which applies the
quality checks (placeholders, script, repetition, length) and drops anything
that fails, so English is shown instead of a doubtful translation.

  python tools/i18n_translate_offline.py --model DIR --spm DIR/spiece.model \\
      --languages tools/i18n_languages.json --output translations.jsonl
"""
import argparse
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
# Application codes whose MADLAD target tag differs.
MADLAD_TAGS = {"zh-Hans": "zh", "zh-Hant": "zh_Hant", "nb": "no", "fr-CA": "fr_CA", "ms-Arab": "ms_Arab",
               "ms-Arab-BN": "ms_Arab_BN", "nds-NL": "nds_NL", "nan-Latn-TW": "nan_Latn_TW", "az-RU": "az_RU",
               "tly-IR": "tly_IR", "ndc-ZW": "ndc_ZW", "kr-Arab": "kr_Arab", "ks-Deva": "ks_Deva",
               "bjn-Arab": "bjn_Arab", "ace-Arab": "ace_Arab", "taq-Tfng": "taq_Tfng", "crh-Latn": "crh_Latn",
               "ber-Latn": "ber_Latn", "gom-Latn": "gom_Latn", "kaa-Latn": "kaa_Latn", "kmz-Latn": "kmz_Latn",
               "ctd-Latn": "ctd_Latn", "cr-Latn": "cr_Latn", "sat-Latn": "sat_Latn"}


def madlad_tag(code):
    return MADLAD_TAGS.get(code, code.replace("-", "_"))


def protect(message):
    """Replace {name} fields with numbered markers the model copies through.

    Returns the protected text and the ordered field names to restore."""
    names = []

    def marker(match):
        names.append(match.group(1))
        return f"[{len(names) - 1}]"

    return PLACEHOLDER.sub(marker, message), names


def restore(translated, names):
    """Put {name} fields back; None if any marker is missing or duplicated."""
    for index in range(len(names)):
        if translated.count(f"[{index}]") != 1:
            return None
    for index, name in enumerate(names):
        translated = translated.replace(f"[{index}]", "{" + name + "}")
    if re.search(r"\[\d+\]", translated):
        return None
    return translated


def done_pairs(path):
    finished = set()
    if path.exists():
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    row = json.loads(line)
                    finished.add((row["language"], row["source"]))
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
    return finished


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", type=Path, required=True, help="CTranslate2 model directory")
    parser.add_argument("--spm", type=Path, required=True, help="MADLAD sentencepiece model")
    parser.add_argument("--languages", type=Path, required=True, help="JSON list (or object) of application codes")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=48)
    parser.add_argument("--threads", type=int, default=0, help="CPU threads (0 = CTranslate2 default)")
    parser.add_argument("--beam-size", type=int, default=1, help="1 (greedy) suits short interface strings")
    args = parser.parse_args()
    try:
        import ctranslate2
        import sentencepiece
    except ImportError as error:
        raise SystemExit("Install ctranslate2 and sentencepiece in a separate tooling environment") from error

    source = json.loads((ROOT / "serviceops_core/locales/source.json").read_text(encoding="utf-8"))
    messages = sorted((row["id"] for row in source["messages"]), key=len)
    requested = json.loads(args.languages.read_text(encoding="utf-8"))
    codes = [code for code in requested if code != "en"]
    tokenizer = sentencepiece.SentencePieceProcessor(model_file=str(args.spm))
    translator = ctranslate2.Translator(str(args.model), device="cpu", intra_threads=args.threads)
    finished = done_pairs(args.output)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("a", encoding="utf-8") as output:
        for code in codes:
            pending = [message for message in messages if (code, message) not in finished]
            started = time.monotonic()
            for offset in range(0, len(pending), args.batch_size):
                batch = pending[offset:offset + args.batch_size]
                protected = [protect(message) for message in batch]
                tokens = [tokenizer.encode(f"<2{madlad_tag(code)}> {text}", out_type=str) for text, _ in protected]
                results = translator.translate_batch(
                    tokens, beam_size=args.beam_size, max_decoding_length=min(512, 32 + 4 * max(len(row) for row in tokens)),
                    repetition_penalty=1.1)
                for message, (_, names), result in zip(batch, protected, results):
                    text = tokenizer.decode(result.hypotheses[0]).strip()
                    restored = restore(text, names) if names else text
                    if restored is not None:
                        output.write(json.dumps({"language": code, "source": message, "translation": restored},
                                                ensure_ascii=False) + "\n")
                output.flush()
            print(json.dumps({"language": code, "messages": len(pending),
                              "seconds": round(time.monotonic() - started, 1)}), flush=True)
    return 0


def to_catalog_input(jsonl_path, json_path):
    """Convert the JSON-lines output into catalogs --input format."""
    layers = {}
    with Path(jsonl_path).open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            layers.setdefault(row["language"], {})[row["source"]] = row["translation"]
    Path(json_path).write_text(json.dumps(layers, ensure_ascii=False) + "\n", encoding="utf-8")
    return {code: len(rows) for code, rows in layers.items()}


if __name__ == "__main__":
    sys.exit(main())
