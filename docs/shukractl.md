# shukractl

Walkthroughs: [tutorials](tutorials/README.md).

Operator CLI for Shukra. Same shape as Netra's `netractl`: banner, grouped help, human boards, `--json`. It does not load BPF.

```bash
shukractl --help
shukractl status
shukractl status --json
shukractl trace kvm --vm payment-prod-03
shukractl isolate payment-prod-03
```

`isolate` prints the audit record and states that enforcement is not attached.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `SHUKRA_URL` | `http://127.0.0.1:30970` | Daemon base URL |
| `SHUKRA_API_KEY` | `~/.shukra/api-key` if unset | Bearer token |
| `SHUKRA_TLS_INSECURE` | auto on https loopback | Skip verify for a self-signed cert |
| `SHUKRA_CLI_COLOR` | on for a TTY | `false` disables color |
| `SHUKRA_CLI_NO_BANNER` | unset | Hide the banner |
| `NO_COLOR` | unset | Disable color |

`~/.shukra/env` is loaded when a variable is not already set. `SHUKRA_SKIP_DOTENV=1` skips that file.

## Install

```bash
make install
shukractl install-cli --prefix "$HOME/.local"
```
