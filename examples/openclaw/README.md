# OpenClaw example

Production-ready config for running [OpenClaw](https://github.com/openclaw/openclaw) inside a agentcage sandbox with secret injection, domain allowlisting, and entropy/content-type inspectors.

```bash
cp examples/openclaw/config.yaml config.yaml
agentcage secret set openclaw ANTHROPIC_API_KEY
agentcage cage create -c config.yaml
```

See [OpenClaw setup guide](../../docs/openclaw.md) for the full walkthrough.
