# Monitoring and alerting

`prometheus-rules.yaml` is the alert rule set ServiceOps ships and
maintains (`ServiceOpsUnavailable`, `ServiceOpsWorkerDown`,
`ServiceOpsErrorsDetected`, `ServiceOpsHigh5xxRate`,
`ServiceOpsSyntheticLoginFailed`, `ServiceOpsBackupStale`). The Prometheus
server and Alertmanager instance that load and act on these rules are the
deploying organization's own infrastructure — ServiceOps does not run or
ship them.

## Resolved-alert notifications

If a resolved notification (`"status": "resolved"`) for one of these alerts
doesn't seem to reach your receiver, check your Alertmanager **route**
configuration before suspecting Prometheus. A real, isolated rehearsal
against these exact rules found the delay was never in Prometheus's own
alert `EndsAt` tracking — that always cleared correctly and immediately.
The two settings that actually govern how fast a resolved notification
reaches a receiver are Alertmanager's own `group_interval` (how often a
notification group is re-evaluated) and `send_resolved` on the specific
receiver config:

```yaml
route:
  receiver: your-receiver
  group_wait: 30s
  group_interval: 30s      # lower = faster resolved notifications; the
                            # default (5m) can make a resolved alert feel
                            # like it never arrives if you're only watching
                            # for a minute or two
  repeat_interval: 4h
receivers:
  - name: your-receiver
    webhook_configs:
      - url: "https://your-receiver.example/hook"
        send_resolved: true   # required per-receiver; a global default is
                               # not enough for every Alertmanager version
```

In a rehearsal with `group_interval: 5s` and an explicit
`send_resolved: true`, the resolved notification for `ServiceOpsWorkerDown`
arrived within seconds of the underlying condition clearing, confirmed
twice. `resolve_timeout` (Alertmanager's global config) is a fallback for
older-style alerts without an explicit `EndsAt` and did **not** affect
resolution timing for these rules in testing — don't spend time tuning it
for this.

## Reference `alertmanager.yml`

A minimal, tested starting point (replace the receiver with your own):

```yaml
global:
  resolve_timeout: 5m

route:
  receiver: default
  group_wait: 30s
  group_interval: 2m
  repeat_interval: 4h

receivers:
  - name: default
    webhook_configs:
      - url: "https://your-receiver.example/hook"
        send_resolved: true
```
