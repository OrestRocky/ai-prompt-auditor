import argparse
import json
import sys
from .audit import audit_prompt


def main() -> int:
    parser = argparse.ArgumentParser(prog="ai-prompt-auditor", description="Detect potential secret leakage in prompts.")
    parser.add_argument("--text", type=str, help="Prompt text to audit.")
    parser.add_argument("--file", type=str, help="Path to a text file containing the prompt.")
    parser.add_argument("--json", action="store_true", help="Output JSON.")
    args = parser.parse_args()

    if not args.text and not args.file:
        parser.print_help()
        return 2

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        text = args.text

    report = audit_prompt(text)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"RISK SCORE: {report['risk_score']}/100\n")
        if report["findings"]:
            print("FINDINGS:")
            for f in report["findings"]:
                print(f"- {f['name']} (severity {f['severity']}): {f['description']} | matches: {f['matches_count']}")
        else:
            print("FINDINGS: none detected")

        print("\nRECOMMENDATIONS:")
        for r in report["recommendations"]:
            print(f"- {r}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
