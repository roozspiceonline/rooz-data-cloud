# RDC Phase 1I canary Agent

This fixture is the only reference Agent intended for the first controlled
sandbox activation. It has no secrets, no network, no browser, no datasets,
no key-value store, and no request queue.

The Agent reads `/rdc/input/input.json` and writes
`/rdc/output/output.json`. Its output is deterministic and uses only the
Python standard library.

Build the upload ZIP with:

```bash
python3 scripts/build-phase1i-canary-source.py
```

Create the RDC Agent with slug `rdc-canary` so the Phase 1G source validator
can match `agent.json` to the immutable Agent identity.
