"""Equipment identification stays offline and distinguishes types from exact models."""
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from serviceops_core.equipment_artwork import CATEGORIES, identify_equipment, local_device_artwork


@pytest.mark.parametrize('vendor,model,expected', [
    ('Dell Technologies', 'Dell PowerEdge R640', 'dell-poweredge-r640'),
    ('DELL EMC', 'PowerEdge R640', 'dell-poweredge-r640'),
    ('Cisco Systems, Inc.', 'Cisco C9300_48P', 'cisco-c9300-48p'),
    ('Juniper Networks', 'EX4300–48P', 'juniper-ex4300-48p'),
    (None, 'Dell PowerEdge R640', 'dell-poweredge-r640'),
    ('HP', 'Dell PowerEdge R640', None),
    ('Dell', 'PowerEdge R6400', None),
    ('Cisco', 'C9300-48T', None),
    ('Dell', 'R640 backup', None),
    (None, 'R640', None),
])
def test_exact_model_matching_is_normalized_but_not_fuzzy(vendor, model, expected):
    assert local_device_artwork(vendor, model) == expected


@pytest.mark.parametrize('ci_class,model,name,attributes,kind,basis', [
    ('Server', 'Unknown', 'db01', {}, 'server', 'CI class'),
    ('Device', None, 'edge01', {'NetBox: Role': 'Core switch'}, 'switch', 'Recorded role'),
    ('Server', None, 'host', {'NetBox: Role': 'Storage array'}, 'storage', 'Recorded role'),
    ('Device', 'PowerEdge R750', 'host', {}, 'server', 'Model family'),
    ('Device', 'FortiGate 100F', 'edge', {}, 'firewall', 'Model family'),
    ('Device', 'Smart-UPS 3000', 'power', {}, 'ups', 'Model family'),
    ('Device', 'Unknown', 'rack-pdu-01', {}, 'pdu', 'Name hint'),
    ('Device', None, 'switchboard', {}, 'unknown', 'No recognized equipment metadata'),
    ('Device', None, 'sanctuary', {}, 'unknown', 'No recognized equipment metadata'),
    ('Console Switch', None, 'console', {}, 'kvm', 'CI class'),
    ('Device', None, 'unknown', {'role': 'Fiber Patch Panel'}, 'patch-panel', 'Recorded role'),
    ('Device', None, 'unknown', {'equipment_type': 'Blade Chassis'}, 'blade', 'Recorded role'),
    ('Device', None, '<script>alert(1)</script>', None, 'unknown', 'No recognized equipment metadata'),
])
def test_identification_uses_specific_evidence_and_word_boundaries(ci_class, model, name, attributes, kind, basis):
    identified = identify_equipment(ci_class, model=model, name=name, attributes=attributes)
    assert identified['kind'] == kind
    assert identified['basis'] == basis


@pytest.mark.parametrize('kind', [kind for kind, _, _ in CATEGORIES] + ['unknown'])
def test_every_category_has_safe_front_and_rear_local_artwork(kind):
    for face in ('front', 'rear'):
        path = Path(__file__).resolve().parents[1] / 'static' / 'device-artwork' / f'generic-{kind}.{face}.svg'
        root = ET.fromstring(path.read_text())
        assert root.attrib['viewBox'] == '0 0 320 36'
        assert 'type illustration' in root.find('{http://www.w3.org/2000/svg}title').text
        assert not any(node.tag.endswith(('script', 'foreignObject', 'image')) for node in root.iter())
        assert not any('href' in attr for node in root.iter() for attr in node.attrib)
