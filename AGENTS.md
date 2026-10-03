# ServiceOps delivery requirements

- The acceptance deployment is the local MicroK8s cluster, namespace `operations`, exposed as `serviceops.wijesundara.com`. Local Docker Compose is not a delivery target.
- Do not commit, push, tag, publish, or start GitHub pipelines unless the user explicitly asks in that request. Make requested changes in the working tree and deploy them directly to the local MicroK8s cluster.
- Every implementation must pass appropriate local functional, security, migration, and browser/accessibility gates before deployment.
- A locally built image (in-cluster registry, by digest) is only a temporary acceptance candidate. Once pushed, production runs the Governed release image from GHCR by digest, with the chart from the same tag.
- Deploy through Helm with `--wait` and **without `--atomic`**: the migration job commits schema changes first, so an automatic rollback leaves old pods that refuse the new schema. Roll forward on failure. Never use `kubectl set image`, an unversioned image, or application-startup migrations.
- Only one agent deploys at a time: confirm no other `helm` process is running and no `pending-*` Helm revision exists before upgrading.
- Never edit version files or create tags by hand; the Governed release workflow owns versions.
- Before an upgrade, create and restore-test a PostgreSQL backup and record its reference. Preserve the existing database and uploads PVCs.
- After deployment, verify web and worker rollout status, `/health`, `/ready`, the Alembic head, the retained Helm test, public Cloudflare Access, and recent logs. A skipped live check is a verification gap.
- Kubernetes environment values are maintained in `/Users/anushka/Github/k8s/serviceops-values-microk8s.yaml`; never commit Secret values.
