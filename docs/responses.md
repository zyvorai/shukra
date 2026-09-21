# Responses: acting on a detection, safely

A detection tells a person something is wrong. A **response** can also do something about it, and the only thing it can do is **isolate the VM**. Because that cuts a running workload off from its network, everything about a response is built so that it cannot do it by accident:

- **By default it only proposes.** A person approves each one. Nothing is done to the VM until they do, and a proposal that nobody decides lapses.
- **Acting on its own is opt-in and named.** `mode: enforce` must name the detection rules it answers. It is refused to answer "any high detection".
- **Guardrails apply to every response**, however it was triggered: protected VMs, a cooldown, an hourly cap, and a timed release.
- **Everything is recorded and announced**, so a person hears about it and can see why.

It needs the same thing isolate does: a management allow list (`-isolate-allow`) and the tap program. Without them every action except a dry run is refused with that reason, and `shukractl doctor` says so (`responses`). A dry run is recorded before that check, so it works on a host where isolate does not, and is the way to try a response there.

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

The first response in the file that matches a detection answers it, so put the narrow ones first. A detection that names no VM is never answered.

`rules` names detection rules exactly. The ones Shukra raises itself:

| Rule | From | Severity |
|---|---|---|
| `unexpected-exec` | A VMM started a program that is not on the allow list | high |
| `new-destination`, `new-dns-suffix`, `new-inbound-peer` | [Learned baselines](baselines.md) | medium, low, medium (configurable) |
| `baseline-cap`, `baseline-forgotten` | Baselines | low |
| `vmm-sensitive-open`, `vmm-syscall`, `vmm-flood` | [VMM tripwires](vmm-tripwires.md) | critical or high, as there |
| `egress-policy-audit`, `egress-policy-blocked` | [Egress policy](egress-policy.md) | low, medium |
| `policy-applied`, `policy-confirmed`, `policy-reverted`, `policy-removed` | Egress policy changes | low or medium |

The rest are yours: the `name` of a `destinations`, `ports`, `dns`, `tls` or `thresholds` rule. The `action-*` announcements are never answered.

## The flow

```text
detection  →  response matches  →  guardrails  →  propose  →  a person approves  →  isolated
                                       │                            │ rejects, or nobody: nothing is done
                                       └→ enforce ──────────────────────────────────→ isolated
```

**Propose** (the default). The action is `pending`, an `action-proposed` detection announces it (to the console, the CLI and every alert sink, so a webhook can page a person), and the incident bundle is captured so the person has something to decide on. The bundle is the one `shukractl incident <vm>` would give at that moment, over the 15 minutes before it: the verdict (which covers the last five minutes), the window's detections, up to 500 recorder events, the VM's isolations, the allow list and the programs.

```bash
shukractl actions                      # what waits for a decision
shukractl actions --bundle a-3         # the evidence: verdict, detections, recorder events
shukractl approve a-3                  # isolate the VM
shukractl reject a-3                   # do nothing
```

```text
$ shukractl actions
ACTIONS  1 waiting for a decision
  a-3  pending  vm=web-01  response=contain-miners (propose)  for crypto-pool [high]
      crypto-pool: looked up pool.nanopool.org (A)
      lapses 2026-09-20T03:30:00Z: shukractl approve a-3  or  shukractl reject a-3  (evidence: shukractl actions --bundle a-3)
```

The Actions page in the console does the same, with a confirmation that names the VM and the consequence. Approving checks the guardrails **again**: the VM may have been protected, or isolated by someone else, since it was proposed.

**Enforce.** Only with `mode: enforce`, and only for the rules it names. The action is carried out at once, and the response is recorded as the decider (`auto:<response>:<id>`).

**Dry run.** `dry_run: true` records what would have been done (`dry_run` status, an `action-dry-run` announcement) and changes nothing, whatever `mode` says. It is the way to try a response out on real detections, and the only mode that may answer any detection without naming rules.

```yaml
responses:
  - name: try-miners
    rules: [crypto-pool]
    action: isolate
    mode: enforce               # what it would do once dry_run is removed
    dry_run: true               # records it, changes nothing
```

## The guardrails

| Guardrail | What it does | What you see |
|---|---|---|
| **`never_isolate`** | No response may isolate a listed VM, not even an approved proposal | `refused`, guardrail `never_isolate` |
| **Isolate must work** | Nothing is attempted unless the daemon can really isolate. A dry run is recorded before this check, and a protected VM is refused before it | `refused`, guardrail `isolate_unavailable`, with the reason (no `-isolate-allow`, tap program not attached) |
| **`max_per_hour`** | At most this many isolations carried out **automatically** in a rolling hour. A person's approval is not counted: it is their decision | `refused`, guardrail `max_per_hour` |
| **`cooldown`** | After a response makes an action for a VM it leaves that VM alone for this long, so a detection storm is one action and not hundreds. It starts when the action is made, so a proposal nobody decides, a refusal and a dry run hold it too. It is per VM and response | nothing: the repeat is ignored |
| **One at a time** | A VM with a proposal waiting gets no second one, and a VM that is already isolated is not isolated again | nothing |
| **`expire`** | An unanswered proposal lapses and can no longer be approved, even by a request that arrives before the daemon has noticed. Lapsing is noticed every 5 seconds | `expired` |
| **`release_after`** | The VM is released again after this long, by `auto:<id>:timer`. The release time is stored with the action, so a restart neither forgets nor extends it: an isolation that should have ended while the daemon was down ends on the first tick (every 5 seconds). A person who releases the VM early does not cancel the timer, so it releases the VM again when it comes due, which would also lift an isolation someone made in between | `released` |
| **Never a response to a response** | The announcements a response makes (`action-*`) are never answered by any response | |

The management allow list stays reachable while a VM is isolated, exactly as for `shukractl isolate`, so a person can still get at it.

## What is recorded

Every decision is an **action** with an id (`a-1`, `a-2`, ...): the response, the detection that set it off, when, who decided (`admin:f72c1a (shukractl)` or `auto:contain-miners:a-3`), what the isolate request answered, and the release time. "Who" is the key id of the bearer key that authenticated, plus the optional `X-Shukra-Actor` label. It is not a person's name. The same record keeps the role, source address, request id and operation. They are appended to `actions.jsonl` under `-data-dir`, and each action keeps the incident bundle it was made on in `incidents/<id>.json` (mode 0600, the newest 200). The files are written and then synced, and the directory is synced after that. If isolate or enforce succeeded and that write failed, the action is `executed_audit_degraded`: the VM is contained, and `shukractl doctor` fails `audit-persist`. `shukra_audit_persist_failures_total` counts those failures. The isolation itself is in the isolate audit trail under the same principal, so `GET /api/v1/isolations` says which action caused it.

Each step is also announced as a detection so nobody has to poll. They go to every sink like any other detection:

| Announcement | Severity | When |
|---|---|---|
| `action-proposed` | medium | A proposal is waiting. The message names the command that approves it and how long it has |
| `action-executed` | high | A VM was isolated, by approval or by an enforcing response. Says when it releases itself |
| `action-refused` | low | A guardrail, or the isolate request itself, said no |
| `action-rejected` | low | A person declined |
| `action-expired` | low | Nobody decided in time |
| `action-released` | low | `release_after` released the VM |
| `action-dry-run` | low | A dry run recorded what it would have done |

They are what a webhook should page on, and the only one that means a VM was cut off is `action-executed`.

## What can go wrong, and what stops it

- **A detection that is wrong.** The reason proposals are the default. With `enforce`, keep the rules narrow, set `release_after`, and try it as `dry_run` first.
- **A guest that triggers it to hurt itself or a neighbour.** A guest can cause a detection, so it can cause an isolation of **itself** through an `enforce` response. `cooldown`, `max_per_hour` and `release_after` bound how often, and `never_isolate` protects the VMs that must never go. It cannot cause an isolation of another VM: a detection names the VM whose tap it was seen on.
- **A storm.** The hourly cap and the cooldown; and the queue the engine reads detections from is bounded, so the event path never waits.
- **The daemon restarting.** Pending proposals are restored and still lapse on time. Isolation itself is pinned in the kernel and outlives the daemon.

## How do I know it works

1. **The file says what you think.** `shukractl rules check <file>` prints each response and how it acts (`contain-miners (propose)`, `auto (enforce)`, `try (dry run)`), and a line for every response that isolates on its own. `shukractl doctor --json` has a `responses` check that is `ok` and says how many propose, enforce and dry-run.
2. **It would fire, without doing anything.** Add `dry_run: true` to the response, reload, and cause the detection it names on a test VM. `shukractl actions --all` shows an action with status `dry_run` and the VM is untouched, and an `action-dry-run` detection appears in `shukractl security <vm>`.
3. **A proposal is a proposal.** Take `dry_run` off and cause it again. `shukractl actions` shows it `pending`, the VM is still reachable, `shukractl actions --bundle <id>` has the evidence, and `shukractl reject <id>` ends it with nothing done.
4. **Approval works, and releases.** On a disposable VM, `approve` it: the action is `executed`, `shukractl trace tap --vm <vm>` shows `isolated=true`, and `shukractl release <vm>` (or the response's `release_after`) undoes it.
5. **The counters agree.** `shukra_actions_pending` and `shukra_actions{status}` on `/metrics` (present only while responses are configured) match `shukractl actions --all`.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| A detection fired and nothing was proposed | No response answers it: `rules` does not name it exactly, its severity is under `min_severity`, it names no VM, another response earlier in the file took it, or the VM already has a pending proposal, is inside the cooldown, or is already isolated | `shukractl actions --all`, and the rule's name in `shukractl security <vm>` |
| `action-refused ... isolate is not enabled` (`isolate_unavailable`) | No `-isolate-allow`, or the tap program is not attached | `shukractl doctor` (`isolate`, `responses`). A dry run still works |
| `refused`, guardrail `never_isolate` | The VM is on the list, even for an approved proposal | Intended. Take it off the list if it is not |
| `refused`, guardrail `max_per_hour` | Automatic isolations reached the cap in the last hour | Wait, raise `max_per_hour` (1 to 100), or narrow the response. A person's approval is not counted |
| `refused`, guardrail `isolate_refused` | The isolate request itself was refused: the VM has no tap, is unknown, or the kernel took it on some taps only (what took effect is kept, as for `shukractl isolate`) | The action's `result` line has the reason, as `shukractl isolate` would |
| `refused`, "already isolated" | Someone isolated it after the proposal was made | Nothing to do |
| `approve` says the proposal expired | It sat longer than `expire` | The detection has to fire again after the cooldown |
| `approve` says the action is not waiting for a decision (409) | It was decided already | `shukractl actions --all` |
| `rules check` refuses `mode: enforce` | An enforcing response must name its `rules`, unless it is a dry run | Name them. Answering "any high detection" on its own is a decision for a person |
| Actions vanish from `shukractl actions --all` after a while | The list keeps the newest 500 in memory; `actions.jsonl` restores the last 2,000 records at start | The file under `-data-dir` has the history |

## Limits

| What | Limit |
|---|---|
| `release_after` | 1 minute to 24 hours, or absent for no release |
| `cooldown` | 1 minute to 168 hours (7 days). Default 1 hour |
| `expire` | 1 minute to 24 hours. Default 30 minutes |
| `guardrails.max_per_hour` | 1 to 100. Default 3. Counts automatic isolations only, over a rolling hour, and survives a restart |
| Actions held in memory | 500 (the oldest are dropped) |
| Actions restored at start | The last 2,000 records of `actions.jsonl` |
| Incident bundles | 50 in memory, 200 on disk (`incidents/<id>.json`, the newest by id) |
| Bundle window | 15 minutes before the detection, up to 500 recorder events |
| Detections waiting for the engine | 256. If a storm fills the queue, the excess is dropped and counted, and the cap and cooldown would have held anyway |
| Timer tick | 5 seconds, for proposals lapsing and releases falling due |

## What it does not do

- It has **one action**, isolate. It does not stop a VM, kill a process or change a firewall.
- It does not undo an approval: release is `shukractl release <vm>`, or the response's own `release_after`.
- It does not weigh evidence. It answers the rules you name, and the person approving reads the bundle.
- **Isolation cuts the guest's network at its tap.** It does not stop a process on the host, so a response to a [VMM tripwire](vmm-tripwires.md#from-a-tripwire-to-a-response) contains a guest that is talking out and is not a substitute for looking at the host. It does not undo an [egress policy](egress-policy.md) either: isolation wins over a policy while it lasts, and releasing leaves the policy as it was.
- It does not say who a person was. See [What is recorded](#what-is-recorded).

## Where it is

`shukractl actions [--all] [--bundle <id> [--out FILE]]`, `approve <id>`, `reject <id>`; `GET /api/v1/actions`, `POST /api/v1/actions/<id>/approve` and `/reject` (admin key only), `GET /api/v1/actions/<id>/incident`; the Actions page; `/metrics`: `shukra_actions_pending` and `shukra_actions{status}` (present only while responses are configured).

See also: [Guest traffic and isolation](tap.md#isolate), which is what an action does to a VM and what it outlives; [VMM tripwires](vmm-tripwires.md) and [learned baselines](baselines.md), whose detections a response can name; [doctor](doctor.md), for the `responses` check; and [Investigate after the fact](tutorials/09-after-the-fact.md), which reads the same incident bundle a proposal carries.
