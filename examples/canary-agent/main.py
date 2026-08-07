from __future__ import annotations

import json
import os
from pathlib import Path


def main() -> None:
    input_path = Path(os.environ["RDC_INPUT_PATH"])
    output_path = Path(os.environ["RDC_OUTPUT_PATH"])
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    message = str(payload["message"])
    values = [int(value) for value in payload["values"]]
    output = {
        "canary": "rdc-phase1i",
        "echo": message,
        "count": len(values),
        "sum": sum(values),
    }
    output_path.write_text(
        json.dumps(output, sort_keys=True),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
