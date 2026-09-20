# Responses: acting on a detection, safely

A detection tells a person something is wrong. A **response** can also do something about it, and the only thing it can do is **isolate the VM**. Because that cuts a running workload off from its network, everything about a response is built so that it cannot do it by accident:

- **By default it only proposes.** A person approves each one. Nothing is done to the VM until they do, and a proposal that nobody decides lapses.
- **Acting on its own is opt-in and named.** `mode: enforce` must name the detection rules it answers. It is refused to answer "any high detection".
- **Guardrails apply to every response**, however it was triggered: protected VMs, a cooldown, an hourly cap, and a timed release.
- **Everything is recorded and announced**, so a person hears about it and can see why.

It needs the same thing isolate does: a management allow list (`-isolate-allow`). Without one, every action is refused with that reason, and `shukractl doctor` says so (`responses`).

## Turning it on

```yaml
responses:
  - name: contain-miners
    rules: [crypto-pool]        # the detection rules it answers: yours, or new-destination and so on
    action: isolate
    mode: propose               # propose (the default) or enforce
    min_severity: high          # optional floor
    release_after: 15m          # optional: release the VM again by itself
    cooldown: 1h                # leave a VM alone this long after acting on it (default 1h)
    expire: 30m                 # a proposal lapses if nobody decides (default 30m)
guardrails:
  never_isolate: [db-primary]   # no response may isolate these, approved or not
  max_per_hour: 3               # automatic isolations per hour, in all (default 3)
```

`shukractl rules check` says what each response will do, and warns about one that acts on its own. `systemctl reload shukra` applies it, and a mistake in the file leaves the previous rules in force. A response answers a detection whose rule name is in `rules` (at or above `min_severity` if you give one). With no `rules` it answers any detection at or above `min_severity`, which defaults to `high`; that is only allowed for `propose` and `dry_run`.

The first response in the file that matches a detection answers it, so put the narrow ones first.

## The flow

```text
detection  →  response matches  →  guardrails  →  propose  →  a person approves  →  isolated
                                       │                            │ rejects, or nobody: nothing is done
                                       └→ enforce ──────────────────────────────────→ isolated
```

**Propose** (the default). The action is `pending`, an `action-proposed` detection announces it (to the console, the CLI and every alert sink, so a webhook can page a person), and the incident bundle is captured so the person has something to decide on:

```bash
shukractl actions                      # what waits for a decision
shukractl actions --bundle a-3         # the evidence: verdict, detections, recorder events
shukractl approve a-3                  # isolate the VM
shukractl reject a-3                   # do nothing
```

The Actions page in the console does the same, with a confirmation that names the VM and the consequence. Approving checks the guardrails **again**: the VM may have been protected, or isolated by someone else, since it was proposed.

**Enforce.** Only with `mode: enforce`, and only for the rules it names. The action is carried out at once, and the response is recorded as the decider (`auto:<response>:<id>`).

**Dry run.** `dry_run: true` records what would have been done (`dry_run` status, an `action-dry-run` announcement) and changes nothing, whatever `mode` says. It is the way to try a response out on real detections, and the only mode that may answer any detection without naming rules.

## The guardrails

| Guardrail | What it does | What you see |
|---|---|---|
| **`never_isolate`** | No response may isolate a listed VM, not even an approved proposal | `refused`, guardrail `never_isolate` |
| **Isolate must work** | Nothing is attempted unless the daemon can really isolate | `refused`, guardrail `isolate_unavailable`, with the reason (no `-isolate-allow`, tap program not attached) |
| **`max_per_hour`** | At most this many isolations carried out **automatically** in a rolling hour. A person's approval is not counted: it is their decision | `refused`, guardrail `max_per_hour` |
| **`cooldown`** | After a response acts on a VM it leaves that VM alone for this long, so a detection storm is one action and not hundreds | nothing: the repeat is ignored |
| **One at a time** | A VM with a proposal waiting gets no second one, and a VM that is already isolated is not isolated again | nothing |
| **`expire`** | An unanswered proposal lapses and can no longer be approved, even by a request that arrives before the daemon has noticed | `expired` |
| **`release_after`** | The VM is released again after this long. The release time is stored with the action, so a restart neither forgets nor extends it: an isolation that should have ended while the daemon was down ends on the first tick | `released` |
| **Never a response to a response** | The announcements a response makes (`action-*`) are never answered by any response | |

The management allow list stays reachable while a VM is isolated, exactly as for `shukractl isolate`, so a person can still get at it.

## What is recorded

Every decision is an **action** with an id (`a-1`, `a-2`, ...): the response, the detection that set it off, when, who decided (`approved by alice (contain-miners, a-3)` or `auto:contain-miners:a-3`), what the isolate request answered, and the release time. They are appended to `actions.jsonl` under `-data-dir`, and each action keeps the incident bundle it was made on in `incidents/<id>.json` (mode 0600, the newest 200). The isolation itself is in the isolate audit trail under the same actor, so `GET /api/v1/isolations` says which action caused it.

Each step is also announced as a detection so nobody has to poll: `action-proposed`, `action-executed`, `action-refused`, `action-rejected`, `action-expired`, `action-released` and `action-dry-run`. They go to every sink like any other detection.

## What can go wrong, and what stops it

- **A detection that is wrong.** The reason proposals are the default. With `enforce`, keep the rules narrow, set `release_after`, and try it as `dry_run` first.
- **A guest that triggers it to hurt itself or a neighbour.** A guest can cause a detection, so it can cause an isolation of **itself** through an `enforce` response. `cooldown`, `max_per_hour` and `release_after` bound how often, and `never_isolate` protects the VMs that must never go. It cannot cause an isolation of another VM: a detection names the VM whose tap it was seen on.
- **A storm.** The hourly cap and the cooldown; and the queue the engine reads detections from is bounded, so the event path never waits.
- **The daemon restarting.** Pending proposals are restored and still lapse on time. Isolation itself is pinned in the kernel and outlives the daemon.

## What it does not do

- It has **one action**, isolate. It does not stop a VM, kill a process or change a firewall.
- It does not undo an approval: release is `shukractl release <vm>`, or the response's own `release_after`.
- It does not weigh evidence. It answers the rules you name, and the person approving reads the bundle.

## Where it is

`shukractl actions [--all] [--bundle <id> [--out FILE]]`, `approve <id>`, `reject <id>`; `GET /api/v1/actions`, `POST /api/v1/actions/<id>/approve` and `/reject` (admin key only), `GET /api/v1/actions/<id>/incident`; the Actions page; `/metrics`: `shukra_actions_pending` and `shukra_actions{status}` (present only while responses are configured).
