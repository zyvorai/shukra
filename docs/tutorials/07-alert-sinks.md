# Alert sinks

A detection is always in the API, the console and `shukractl security`. A sink also sends it somewhere else. All are off until you ask for them, and any combination can run at once.

```bash
export SHUKRA_WEBHOOK_SECRET="$(openssl rand -hex 32)"
shukrad -webhook-url https://alerts.example.com/shukra \
        -syslog \
        -alert-file /var/log/shukra/alerts.jsonl
```

Each sink has its own queue of 256 and its own goroutine, so a stuck webhook cannot delay the file or syslog sink, and the event path never waits on any of them. If a queue is full the detection is dropped for that sink only and counted.

| Flag | Sends |
|---|---|
| `-webhook-url` | `POST` of the event JSON. Only `http://` and `https://` are accepted |
| `-syslog` | One JSON line to the local syslog daemon, facility `daemon`, tag `shukra`. `critical` is crit, `high` err, `medium` warning, `low` notice |
| `-alert-file` | One JSON line appended to the file, mode `0600`. It rolls to `.1` at 16 MiB |

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

## What to watch

`/metrics` has `shukra_alert_sent_total`, `shukra_alert_failed_total` and `shukra_alert_dropped_total`, each labelled by sink, and `shukra_detections_suppressed_total`. A rising `failed` or `dropped` means alerts are being lost on the way out. They are still in the API and, with `-data-dir`, in `detections.jsonl`.

On shutdown the daemon gives the queues up to five seconds to drain, then cancels what is still retrying.

Sinks are read at start. Changing them needs a restart; the rules in the detection file reload with `systemctl reload shukra`.
