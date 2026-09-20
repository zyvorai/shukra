# Alert sinks

A detection is always in the API, the console and `shukractl security`. A sink also sends it somewhere else. All are off until you ask for them, and any combination can run at once.

```bash
export SHUKRA_WEBHOOK_SECRET="$(openssl rand -hex 32)"
shukrad -webhook-url https://alerts.example.com/shukra \
        -syslog \
        -alert-file /var/log/shukra/alerts.jsonl
```

Run by hand as above, that is all there is to it. Under the shipped systemd unit there are two differences, both because the unit is locked down: flags and the secret go in `/etc/shukra/env`, and the service can write only under `/var/lib/shukra`, so an alert file must be there (a path such as `/var/log/shukra/alerts.jsonl` fails at start with `read-only file system`, and the daemon exits):

```text
SHUKRA_WEBHOOK_SECRET=<the output of openssl rand -hex 32>
SHUKRA_EXTRA_ARGS=-webhook-url https://alerts.example.com/shukra -syslog -alert-file /var/lib/shukra/alerts.jsonl
```

One `SHUKRA_EXTRA_ARGS=` line, with every flag on it ([deploy](03-deploy.md#other-daemon-options)), then `sudo systemctl restart shukra`. The file's directory must already exist: the daemon creates the file, not its parent. If the daemon already has a TLS line there, add these flags to it.

Each sink has its own queue of 256 and its own goroutine, so a stuck webhook cannot delay the file or syslog sink, and the event path never waits on any of them. If a queue is full the detection is dropped for that sink only and counted.

| Flag | Sends |
|---|---|
| `-webhook-url` | `POST` of the event JSON. Only `http://` and `https://` are accepted |
| `-syslog` | One JSON line to the local syslog daemon, facility `daemon`, tag `shukra`. `critical` is crit, `high` err, `medium` warning, `low` notice |
| `-alert-file` | One JSON line appended to the file, mode `0600`. It rolls to `.1` at 16 MiB |

What arrives is every detection, not only your rules': the built-in unexpected-exec check, [VMM tripwires](11-vmm-tripwires.md) (`vmm-sensitive-open` and the others), baseline first sightings, [egress policy](10-egress-policy.md) strays and every `policy-applied`, `policy-confirmed`, `policy-reverted` and `policy-removed`, and a response's `action-proposed` and the rest ([responses](../responses.md)). Route on `rule`.

The payload is the event shape from the API. `rule` is the rule name, so a receiver can route on it without parsing `message`. `guest_attributed` is `true` only for a detection on traffic seen on a VM tap, and `attribution` says which.

## Webhook signature

With `SHUKRA_WEBHOOK_SECRET` set (the secret is read from the environment so it stays out of the process list), each request carries:

```text
X-Shukra-Timestamp: 1758300000
X-Shukra-Signature: sha256=<hex>
```

The signature is HMAC-SHA256 of `"<timestamp>.<body>"`. The timestamp is inside the signed bytes, so a receiver should recompute the MAC and also reject a timestamp more than a few minutes old.

```python
import hmac, hashlib, time
def verify(secret: bytes, ts: str, body: bytes, sig: str) -> bool:
    if abs(time.time() - int(ts)) > 300:
        return False
    want = "sha256=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)
```

Without a secret the requests are sent unsigned and the daemon warns at start.

Delivery: a network error, `429` or `5xx` is retried, three attempts in all with a doubling pause. Any other status is final, and a `3xx` counts as a failure, because a signed body is never re-sent to a location you did not name. Failure messages in the journal do not include the URL, since webhook URLs often carry a token.

## Send a test alert

Do not wait for a real detection to find out that a sink is broken. A detection you can raise on demand and undo is an **audit-mode egress policy**, which drops nothing (needs the tap program and a VM with a tap):

```bash
shukractl policy apply web-01 --mode audit --allow 192.0.2.0/24
shukractl policy remove web-01
```

That raises `policy-applied` and `policy-removed`, both `low`, naming the VM. For the few seconds the policy exists anything the VM starts outside `192.0.2.0/24` is also reported, so use a quiet VM and remove it straight away. Then look at each sink:

```bash
tail -n 2 /var/lib/shukra/alerts.jsonl                 # the file: JSON lines, "rule":"policy-applied"
sudo journalctl -t shukra -n 5                          # syslog, tag shukra: JSON, priority notice for low
curl -s -H "Authorization: Bearer $SHUKRA_API_KEY" "$SHUKRA_URL/metrics" | grep shukra_alert_
```

The metrics are the check that matters: `shukra_alert_sent_total{sink="webhook"}` (and `file`, `syslog`) should have gone up by two, and `shukra_alert_failed_total` and `shukra_alert_dropped_total` should still be zero. A webhook receiver should log two POSTs, each with `X-Shukra-Timestamp` and `X-Shukra-Signature` when a secret is set.

## What to watch

`/metrics` has `shukra_alert_sent_total`, `shukra_alert_failed_total` and `shukra_alert_dropped_total`, each labelled by sink, and `shukra_detections_suppressed_total`. A rising `failed` or `dropped` means alerts are being lost on the way out. They are still in the API and, with `-data-dir`, in `detections.jsonl`.

On shutdown the daemon gives the queues up to five seconds to drain, then cancels what is still retrying.

Sinks are read at start. Changing them needs a restart; the rules in the detection file reload with `systemctl reload shukra`.

> **If it does not work.**
>
> | You see | Do this |
> |---|---|
> | The daemon exits at start with `alert-file: ... read-only file system` or `no such file or directory` | Under the shipped unit the file must be under `/var/lib/shukra`, and its directory must exist |
> | `webhook` fails at start | The URL must begin `http://` or `https://` |
> | The daemon warns `SHUKRA_WEBHOOK_SECRET is unset` | Requests are unsigned. Set the secret in `/etc/shukra/env` |
> | `shukra_alert_failed_total` rises | The receiver returns `4xx` (a final failure), `5xx` or `429` (retried three times), redirects (`3xx`, never followed), or is unreachable. The journal names the error and leaves out the URL |
> | `shukra_alert_dropped_total` rises | The sink's queue of 256 is full: the receiver is too slow. The detections are still in the API and, with `-data-dir`, in `detections.jsonl` |
> | The signature does not verify | Sign `"<timestamp>.<body>"` with the exact bytes received, and read the secret from the same environment |
> | A change to a sink has no effect | Sinks are read at start: `sudo systemctl restart shukra`. Only the rules reload |
> | Nothing arrives and nothing failed | Is there a detection at all? `shukractl security <vm>`. A repeat inside the suppression time is held back before it reaches a sink |

