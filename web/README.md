# Sentinel Control Center

This local Next.js client displays authority owned by the Sentinel FastAPI
backend. It does not make policy or approval decisions itself.

## Local development

Start the UI on the exact hostname allowed by the control API:

```bash
npm run dev -- --hostname 127.0.0.1
```

The backend must be running at `http://127.0.0.1:8000`. Open the fresh pairing
link generated for that backend process; do not replace `127.0.0.1` with
`localhost`, because the protected API intentionally requires the exact origin
`http://127.0.0.1:3000`.

For a disposable demo, keep the UI command running and launch this from the
repository root in a second terminal:

```bash
python3 scripts/week11_control_demo.py
```

The script creates a temporary Git repository with a confined writable `build`
directory, starts the protected API, and opens a one-use pairing link. It never
switches the workspace of an existing backend process.

## Checks

```bash
npm run lint
npm run typecheck
npm run types:check
npm run build
npm run test:e2e
npm run test:e2e:real
SENTINEL_CAPTURE_WEEK11_SCREENSHOTS=1 npm run test:e2e:real
```

The real Playwright flow requires Docker Desktop, the
`sentinel-executor:local` image, the UI on port 3000, and a free port 8000. It
creates and resets `web/test-results/real-control/`, starts FastAPI against that
disposable repository, then proves pairing, task activation, denial with zero
execution, approval with one Docker write, replay safety, and ordered audit
evidence. It does not mock any Sentinel API.

The real test also checks one `h1` per page, duplicate IDs, accessible names for
visible controls, keyboard navigation into Tasks, keyboard approval, visible
focus treatment, and 4.5:1 contrast for text/signal tokens on both app
surfaces. Setting `SENTINEL_CAPTURE_WEEK11_SCREENSHOTS=1` writes the six real
desktop states to `docs/screenshots/week11/`.
