"""The controller needs DNS, its database and scoped API access to start."""
import shutil
import subprocess
from pathlib import Path
import pytest
import yaml


def test_sandbox_controller_network_and_rbac_contract():
    if not shutil.which('helm'):pytest.skip('Helm is required for chart rendering')
    chart=Path(__file__).resolve().parents[1]/'charts/serviceops'
    output=subprocess.check_output(['helm','template','serviceops',str(chart),'--show-only','templates/sandbox-controller.yaml','--set','premium.sandbox.enabled=true','--set','premium.sandbox.storageNode=test-node','--set','image.digest=sha256:'+'a'*64],text=True)
    docs=list(yaml.safe_load_all(output));policy=next(r for r in docs if r['kind']=='NetworkPolicy');rules=policy['spec']['egress']
    assert rules[0]['to'][0]['namespaceSelector']['matchLabels']['kubernetes.io/metadata.name']=='kube-system'
    assert rules[0]['ports']==[dict(protocol='UDP',port=53),dict(protocol='TCP',port=53)]
    assert rules[1]['to'][0]['podSelector']['matchLabels']['app.kubernetes.io/name']=='serviceops-postgresql'
    assert rules[1]['ports']==[dict(protocol='TCP',port=5432)]
    assert {r['port'] for r in rules[2]['ports']}=={443,16443}
    permission=next(r for r in docs if r['kind']=='ClusterRole')['rules'][0]
    assert set(permission['resourceNames'])=={f'serviceops-sandbox-{kind}-slot{slot}' for kind in ('db','uploads') for slot in (1,2)}
    assert permission['verbs']==['get','patch']
