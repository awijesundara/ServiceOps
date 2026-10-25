"""Prevent new page-level geometry overrides of shared controls and section stacks.

Existing legacy declarations are inventoried, not silently grandfathered by file.
Removing an override is allowed; adding or changing one requires centralization.
"""
import json
import re
from pathlib import Path
from tools.build_dark_theme import blocks, declarations, split_selectors, strip_comments

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / 'design_system/legacy-overrides.json'
OWNED = {'height', 'min-height', 'max-height', 'padding', 'padding-block', 'padding-inline',
         'font-size', 'line-height', 'border-radius'}


def overrides(css):
    result = set()
    for selector, body in blocks(strip_comments(css)):
        if selector.startswith('@'):
            result.update(overrides(body))
            continue
        for target in split_selectors(selector):
            last = re.split(r'\s+|>', target.strip())[-1]
            shared_action = re.search(r'\.(?:button|primary)(?![\w-])', last)
            shared_stack = re.search(r'\.(?:ui-stack|dashboard-columns|dashboard-sections)(?![\w-])', last)
            if not (shared_action or shared_stack) or '::' in last:
                continue
            for key, value in declarations(body):
                owned = OWNED if shared_action else {'gap', 'row-gap', 'column-gap', 'margin', 'margin-top', 'margin-bottom', 'margin-block'}
                if key in owned and re.search(r'\d(?:px|rem|em)', value):
                    result.add(f'{target.strip()} | {key}: {value}')
    return sorted(result)


def inventory():
    return {str(path.relative_to(ROOT)): overrides(path.read_text())
            for path in sorted((ROOT / 'static').glob('*.css'))
            if path.name not in {'controls.css', 'dark.css'} and overrides(path.read_text())}


def violations():
    baseline = json.loads(BASELINE.read_text())
    return [f'{path}: {rule}' for path, rules in inventory().items()
            for rule in rules if rule not in baseline.get(path, [])]


if __name__ == '__main__':
    errors = violations()
    if errors:
        raise SystemExit('Move shared geometry to design_system/:\n' + '\n'.join(errors))
