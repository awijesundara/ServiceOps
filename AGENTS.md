# ServiceOps delivery requirements

- The acceptance deployment is the local MicroK8s cluster, namespace `operations`, exposed as `serviceops.wijesundara.com`. Local Docker Compose is not a delivery target.
- Every implementation must pass the governed functional, security, migration, browser/accessibility, packaging, and hosted-CI gates before deployment.
- Deploy only the immutable, provenance-verified release image digest through Helm with `--atomic --wait`; never use `kubectl set image`, an unversioned image, or application-startup migrations.
- Before an upgrade, create and restore-test a PostgreSQL backup and record its reference. Preserve the existing database and uploads PVCs.
- After deployment, verify web and worker rollout status, `/health`, `/ready`, the Alembic head, the retained Helm test, public Cloudflare Access, and recent logs. A skipped live check is a verification gap.
- Kubernetes environment values are maintained in `/Users/anushka/Github/k8s/serviceops-values-microk8s.yaml`; never commit Secret values.
