"""Complete, review-only ticket drafts; resolve references under the current identity."""
from datetime import datetime, timezone
from flask import current_app
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import HTTPException

from serviceops_core import read_access
from serviceops_core.security import redact

TEXT_LIMITS = {'title': 180, 'description': 10000, 'impact': 10, 'urgency': 10,
               'category': 80, 'subcategory': 80, 'change_type': 20,
               'planned_start': 40, 'planned_end': 40, 'implementation_plan': 10000,
               'test_plan': 10000, 'backout_plan': 10000, 'group_name': 180}


def additional_fields(data):
    try:
        result = {key: redact(str(data[key]).strip())[:limit] for key, limit in TEXT_LIMITS.items()
                  if key not in {'title', 'description', 'impact', 'urgency', 'category'} and data.get(key)}
        if result.get('change_type') not in ('Normal', 'Standard', 'Emergency'):
            result['change_type'] = 'Normal'
        sources = data.get('ci_sources', [])
        result['ci_sources'] = [s for s in sources if isinstance(s, str) and s.startswith('S')][:20] if isinstance(sources, list) else []
        for key in ('planned_start', 'planned_end'):
            raw = result.get(key)
            if raw:
                try:
                    moment = datetime.fromisoformat(raw.replace('Z', '+00:00'))
                    if moment.tzinfo is None:
                        raise ValueError('timezone required')
                    result[key] = moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M')
                except ValueError:
                    current_app.logger.warning('AI draft contained an invalid or ambiguous %s', key)
                    result.pop(key, None)
        if result.get('planned_start') and result.get('planned_end') and result['planned_end'] <= result['planned_start']:
            current_app.logger.warning('AI draft contained a reversed planned window')
            result.pop('planned_start')
            result.pop('planned_end')
        return result
    except Exception:
        current_app.logger.exception('AI draft field validation failed')
        raise


def bind_draft(draft, identity, sources, question=None):
    """Use supplied CI evidence and eligible teams; never guess an unseen record."""
    try:
        import app as core
        result = dict(draft)
        known = {s['id']: s['record_id'] for s in sources if s.get('kind') == 'ci'}
        if question:
            import re
            normalized = ' '.join(question.casefold().split())
            named = {s['id'] for s in sources if s.get('kind') == 'ci' and s.get('title') and
                     re.search(r'(?<!\w)' + re.escape(' '.join(s['title'].casefold().split())) + r'(?!\w)', normalized)}
            if named:
                result['ci_sources'] = [s for s in result.get('ci_sources', []) if s in named]
        ids = list(dict.fromkeys(known[s] for s in result.get('ci_sources', []) if s in known))
        cis = {ci.id: ci for ci in read_access.configuration_items(identity).filter(core.ConfigurationItem.id.in_(ids or [-1])).all()}
        result['ci_ids'] = [i for i in ids if i in cis]
        teams = core.team_groups(identity.tenant_id).filter(core.SupportGroup.active.is_(True))
        if result['kind'] == 'change':
            if not core.role_at_least(identity.effective_role, 'admin'):
                teams = teams.filter(core.SupportGroup.id.in_(core.user_support_group_ids(identity) or {-1}))
            rows = [r for r in teams.all() if r.manager and r.manager.active]
        else:
            rows = teams.all()
        chosen = next((r for r in rows if r.name.casefold() == result.get('group_name', '').casefold()), None)
        if chosen is None and result['ci_ids']:
            primary = cis[result['ci_ids'][0]]
            chosen = next((r for r in rows if r.id == primary.support_group_id), None)
        result['group_id'] = chosen.id if chosen else None
        if chosen:
            result['group_name'] = chosen.name
        required = ['group_id']
        if result['kind'] == 'change':
            required += ['ci_ids', 'planned_start', 'planned_end', 'implementation_plan', 'test_plan', 'backout_plan']
        result['missing_fields'] = [key for key in required if not result.get(key)]
        return result
    except HTTPException:
        raise
    except Exception:
        current_app.logger.exception('AI draft reference validation failed')
        raise


def form_values(draft, identity, sources):
    """Reauthorize saved draft references when the user opens the review form."""
    try:
        bound = bind_draft(draft, identity, sources)
        values = MultiDict({key: str(bound[key]) for key in TEXT_LIMITS if bound.get(key) is not None})
        if bound.get('group_id'):
            values['group_id'] = str(bound['group_id'])
        values.setlist('ci_id', [str(i) for i in bound['ci_ids']])
        return values
    except HTTPException:
        raise
    except Exception:
        current_app.logger.exception('AI draft form projection failed')
        raise
