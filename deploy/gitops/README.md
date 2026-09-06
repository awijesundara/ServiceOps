# ServiceOps GitOps deployment

Use a separate, protected environment repository as the desired-state source.
Copy `application.example.yaml`, replace the repository URL, and commit the
ServiceOps chart plus the environment's non-secret values there. Keep runtime
and bootstrap credentials in an external secret manager; values reference only
their Kubernetes Secret names.

Every promotion is a reviewed Git change updating both `image.tag` and
`image.digest`, plus a unique `database.backupReference`. Argo CD self-heals
drift. Automatic pruning is deliberately disabled so a mistaken Git deletion
cannot remove stateful resources. Roll back by reverting the environment-repo
commit, after checking whether the database migration requires restoration.

For canary delivery, install Argo Rollouts first and set
`progressiveDelivery.enabled=true`. Enable its Prometheus analysis only after
setting `progressiveDelivery.prometheus.address`; a 5xx ratio above the
configured threshold aborts promotion. Without the Rollouts CRD, leave the
option disabled and the chart renders a standard Kubernetes Deployment.
