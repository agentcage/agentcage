# OpenClaw example

Production-ready config for running [OpenClaw](https://github.com/openclaw/openclaw) inside a lobstercage sandbox with secret injection, domain allowlisting, and entropy/content-type inspectors.

```bash
cp examples/openclaw/config.yaml config.yaml
lobstercage secret set openclaw ANTHROPIC_API_KEY
lobstercage cage create -c config.yaml
```

See [OpenClaw setup guide](../../docs/openclaw.md) for the full walkthrough.
