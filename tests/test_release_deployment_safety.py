"""Application rollbacks must not cross committed database migration hooks."""
from pathlib import Path
import shutil
import pytest
from tools import verify_supply_chain as supply


@pytest.mark.parametrize('path',['.github/workflows/deploy-kubernetes.yml','tools/install/kubernetes.sh','tools/safe_update_k8s.sh'])
def test_gate_rejects_automatic_application_rollback(tmp_path,monkeypatch,path):
    source=Path(__file__).resolve().parents[1]
    for name in ('Dockerfile','.github/workflows/supply-chain.yml','.github/workflows/deploy-kubernetes.yml','charts/serviceops/values.yaml','charts/serviceops/templates/tests/health-test.yaml','charts/serviceops/templates/deployment.yaml','charts/serviceops/templates/worker.yaml','charts/serviceops/templates/migration-job.yaml','tools/install/kubernetes.sh','tools/safe_update_k8s.sh'):
        # This gate reads content only. Copying mounted-volume file flags can
        # fail on macOS even though the temporary file contents are writable.
        target=tmp_path/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,target)
    monkeypatch.setattr(supply,'ROOT',tmp_path)
    assert supply.verify_supply_chain()['valid']
    target=tmp_path/path
    target.write_text(target.read_text().replace('--wait --timeout 10m','--atomic --wait --timeout 10m'))
    with pytest.raises(RuntimeError,match='must not automatically roll back'):
        supply.verify_supply_chain()
