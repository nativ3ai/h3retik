# Cloud Headless Job Commands

This command family is the cloud-facing headless interface:

- `h3retik estimate`
- `h3retik submit`
- `h3retik run`
- `h3retik status`
- `h3retik logs`
- `h3retik artifacts`

## Required shape

Run-style commands use a single-shot contract:

```bash
h3retik estimate \
  --target https://target.tld \
  --lane web \
  --module recon-httpx \
  --pipeline quick \
  --arg threads=25 \
  --arg depth=2 \
  --budget-usdc 3 \
  --max-minutes 12 \
  --json
```

## API wiring

Set cloud API endpoint:

```bash
export H3RETIK_CLOUD_API="https://api.example.com"
```

If API is not configured (or `--mock` is passed), commands run in local mock mode and persist job metadata under:

- `telemetry/cloud_jobs.json`

## Payment parameters

Default receiver:

- `0x99EEDcE3C87Adf3dE1c9B8B08F1810C168D6E039`

Override if needed:

```bash
export H3RETIK_PAYMENT_RECEIVER="0x..."
```

The expected remote flow is:

1. `estimate` -> quote
2. `submit` -> `pending_payment` + payment instruction
3. payment confirmation handled by backend
4. `status/logs/artifacts` for execution lifecycle

## Notes

- Lanes: `web|local|osint|onchain`
- Budget gate is enforced client-side before `run`.
- Cloud commands are non-TUI and CI/agent friendly.
