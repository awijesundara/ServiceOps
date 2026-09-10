# ServiceOps delivery requirements

- The acceptance deployment is the local MicroK8s cluster, namespace `operations`, exposed as `serviceops.wijesundara.com`. Local Docker Compose is not a delivery target.
- Do not commit, push, tag, publish, or start GitHub pipelines unless the user explicitly asks in that request. Make requested changes in the working tree and deploy them directly to the local MicroK8s cluster.
- Every implementation must pass appropriate local functional, security, migration, and browser/accessibility gates before deployment.
- Deploy a locally built immutable image digest through Helm with `--atomic --wait`; never use `kubectl set image`, an unversioned image, or application-startup migrations.
- Before an upgrade, create and restore-test a PostgreSQL backup and record its reference. Preserve the existing database and uploads PVCs.
- After deployment, verify web and worker rollout status, `/health`, `/ready`, the Alembic head, the retained Helm test, public Cloudflare Access, and recent logs. A skipped live check is a verification gap.
- Kubernetes environment values are maintained in `/Users/anushka/Github/k8s/serviceops-values-microk8s.yaml`; never commit Secret values.
