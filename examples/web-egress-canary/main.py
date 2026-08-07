from __future__ import annotations

import json
import os
from pathlib import Path


def main() -> None:
    input_path = Path(os.environ["RDC_INPUT_PATH"])
    output_path = Path(os.environ["RDC_OUTPUT_PATH"])
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    results = payload.get("_rdc_web_results", [])
    if not isinstance(results, list):
        raise ValueError("Brokered web results are missing.")
    statuses = [
        int(result["status"])
        for result in results
        if isinstance(result, dict) and "status" in result
    ]
    output = {
        "canary": "rdc-phase1j",
        "brokered": True,
        "resultCount": len(results),
        "statuses": statuses,
        "containerNetwork": "none",
    }
    output_path.write_text(
        json.dumps(output, sort_keys=True),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
