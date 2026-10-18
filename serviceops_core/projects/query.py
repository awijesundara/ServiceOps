"""Bounded JQL-style project search; all SQL uses typed bound parameters.

This implements the documented core dialect, not arbitrary Jira plugins,
Lucene expressions, WAS predicates or custom fields.
"""
import calendar
import math
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from flask import current_app
from sqlalchemy import and_, case, false, func, not_, or_, true
from sqlalchemy.orm import joinedload

from serviceops_core.projects import service
from serviceops_core.projects.models import (
    PRIORITIES, Project, ProjectComponent, ProjectStatus, ProjectVersion, WorkItem,
    WorkItemLabel, WorkItemResolution, WorkItemWatcher, WorkItemVote, WorkItemView, WorkItemHistory, ProjectSprint, ProjectSprintItem,
)
from serviceops_models import User, db, now

MAX_QUERY = 4096
MAX_TOKENS = 256
MAX_DEPTH = 16
FIELDS = ('project', 'key', 'type', 'summary', 'description', 'text', 'status', 'category',
          'priority', 'assignee', 'reporter', 'labels', 'parent', 'created', 'updated',
          'start', 'due', 'resolution', 'storyPoints', 'estimate', 'remaining', 'spent',
          'component', 'fixVersion', 'affectsVersion', 'flagged', 'sprint')
ALIASES = {'issuetype':'type', 'issuekey':'key', 'id':'key', 'duedate':'due',
           'startdate':'start', 'createddate':'created', 'updateddate':'updated',
           'statuscategory':'category', 'label':'labels', 'originalestimate':'estimate',
           'remainingestimate':'remaining', 'timespent':'spent', 'affectedversion':'affectsversion', 'issue':'key'}
COLUMNS = {'summary':WorkItem.title, 'description':WorkItem.description,
           'type':WorkItem.item_type, 'created':WorkItem.created_at, 'updated':WorkItem.updated_at,
           'start':WorkItem.start_date, 'due':WorkItem.due_date, 'storypoints':WorkItem.story_points,
           'estimate':WorkItem.estimate_minutes, 'remaining':WorkItem.remaining_minutes,
           'spent':WorkItem.spent_minutes, 'flagged':WorkItem.flagged}
DATES = {'created','updated','start','due'}
NUMBERS = {'storypoints','estimate','remaining','spent'}


class QueryError(ValueError):
    """A client-visible, non-sensitive syntax error with a one-based position."""

    def __init__(self, message, position=1):
        self.position = position
        super().__init__(f'{message} (position {position})')


@dataclass(frozen=True)
class Token:
    text: str
    position: int
    quoted: bool = False


@dataclass(frozen=True)
class CollectionFunction:
    name: str
    args: tuple


def calendar_function(name, args, clock, position):
    """UTC reporting boundaries with bounded, calendar-aware increments."""
    try:
        periods = {'day': 'd', 'week': 'w', 'month': 'M', 'year': 'y'}
        if name == 'now':
            if args: raise QueryError('now takes no arguments', position)
            return clock
        period = next((p for p in periods if name in ('startof'+p, 'endof'+p)), None)
        if period is None: raise QueryError('Unsupported function', position)
        end = name.startswith('endof')
        base = clock.replace(hour=0, minute=0, second=0, microsecond=0)
        if period == 'week': base -= timedelta(days=base.weekday())
        elif period == 'month': base = base.replace(day=1)
        elif period == 'year': base = base.replace(month=1, day=1)
        if end:
            if period == 'day': base += timedelta(days=1)
            elif period == 'week': base += timedelta(days=7)
            elif period == 'month':
                base = base.replace(year=base.year+(base.month == 12), month=base.month % 12+1)
            else: base = base.replace(year=base.year+1)
            base -= timedelta(microseconds=1)
        if args:
            match = re.fullmatch(r'([+-]?\d{1,5})([yMwdhm]?)', args[0])
            if not match: raise QueryError('Expected an increment such as -1M or +2d', position)
            amount, unit = int(match[1]), match[2] or periods[period]
            if unit in ('M', 'y'):
                month_index = base.year*12+base.month-1+amount*(12 if unit == 'y' else 1)
                year, month = divmod(month_index, 12)
                month += 1
                last_day = calendar.monthrange(year, month)[1]
                # Preserve the end-of-month boundary across unequal month lengths.
                day = last_day if end and period in ('month', 'year') and base.day == calendar.monthrange(base.year, base.month)[1] else min(base.day, last_day)
                base = base.replace(year=year, month=month, day=day)
            else:
                base += timedelta(minutes=amount*{'w': 10080, 'd': 1440, 'h': 60, 'm': 1}[unit])
        return base
    except QueryError:
        raise
    except (ValueError, OverflowError):
        raise QueryError('Date increment is outside the supported calendar', position) from None
    except Exception:
        current_app.logger.error('Project query calendar evaluation failed')
        raise


def tokenize(source):
    try:
        if not isinstance(source,str) or len(source)>MAX_QUERY:
            raise QueryError('Query must be text of at most 4096 characters')
        try:
            source.encode('utf-8')
        except UnicodeEncodeError:
            raise QueryError('Query contains invalid Unicode') from None
        if any(ord(ch)<32 and ch not in '\t\r\n' for ch in source):
            raise QueryError('Query contains unsupported control characters')
        tokens=[]; i=0
        while i<len(source):
            if source[i].isspace():
                i+=1; continue
            start=i; ch=source[i]
            if ch in ('"', "'"):
                quote=ch; i+=1; value=''
                while i<len(source) and source[i]!=quote:
                    if source[i]=='\\':
                        i+=1
                        if i==len(source):
                            raise QueryError('Unfinished quoted value',start+1)
                    value+=source[i]; i+=1
                if i==len(source):
                    raise QueryError('Unclosed quoted value',start+1)
                tokens.append(Token(value,start+1,True)); i+=1
            elif ch in '(),':
                tokens.append(Token(ch,i+1)); i+=1
            elif ch in '=!<>~':
                op=source[i:i+2] if source[i:i+2] in ('!=','>=','<=','!~') else ch
                if op=='!':
                    raise QueryError('Expected != or !~',i+1)
                tokens.append(Token(op,i+1)); i+=len(op)
            else:
                match=re.match(r'[^\s(),=!<>~\'\"]+',source[i:])
                if not match:
                    raise QueryError('Unexpected character',i+1)
                word=match.group(); tokens.append(Token(word,i+1)); i+=len(word)
            if len(tokens)>MAX_TOKENS:
                raise QueryError('Query is too complex',start+1)
        return tokens
    except QueryError:
        raise
    except Exception:
        current_app.logger.error('Project query tokenization failed')
        raise


class Parser:
    def __init__(self, source, user):
        self.tokens=tokenize(source); self.index=0; self.user=user
        self.clock=now().astimezone(timezone.utc)

    def peek(self, word=None):
        if self.index>=len(self.tokens):
            return False if word else None
        token=self.tokens[self.index]
        return (not token.quoted and token.text.upper()==word) if word else token

    def pop(self):
        if not self.peek():
            raise QueryError('Unexpected end of query',self.tokens[-1].position+1 if self.tokens else 1)
        token=self.tokens[self.index]; self.index+=1
        return token

    def require(self, word):
        token=self.pop()
        if token.quoted or token.text.upper()!=word:
            raise QueryError('Expected '+word,token.position)
        return token

    def parse(self):
        predicate=true() if not self.peek() or self.peek('ORDER') else self.expression(0)
        order=[]
        if self.peek('ORDER'):
            self.pop(); self.require('BY')
            while True:
                token=self.pop(); field=self.field(token)
                column=self.order_column(field,token)
                direction=self.pop().text.upper() if self.peek('ASC') or self.peek('DESC') else 'ASC'
                order.append(column.desc().nullslast() if direction=='DESC' else column.asc().nullslast())
                if not self.peek(','):
                    break
                self.pop()
                if len(order)>=3:
                    raise QueryError('Sort by at most three fields',token.position)
        if self.peek():
            raise QueryError('Unexpected query term',self.peek().position)
        return predicate, order+[WorkItem.id.asc()]

    def expression(self, depth):
        result=self.conjunction(depth)
        while self.peek('OR'):
            self.pop(); result=or_(result,self.conjunction(depth))
        return result

    def conjunction(self, depth):
        result=self.unary(depth)
        while self.peek('AND'):
            self.pop(); result=and_(result,self.unary(depth))
        return result

    def unary(self, depth):
        if depth>MAX_DEPTH:
            raise QueryError('Query nesting is too deep',self.peek().position if self.peek() else 1)
        if self.peek('NOT'):
            self.pop(); return not_(self.unary(depth+1))
        if self.peek('('):
            self.pop(); result=self.expression(depth+1); self.require(')'); return result
        return self.clause()

    def field(self, token):
        field=token.text.lower(); field=ALIASES.get(field,field)
        if field not in {f.lower() for f in FIELDS}:
            raise QueryError('Unsupported field',token.position)
        return field

    def sprint_items(self, condition):
        tree = db.session.query(WorkItem.id.label('id'), WorkItem.project_id.label('project_id')).join(
            ProjectSprintItem, ProjectSprintItem.work_item_id == WorkItem.id).join(
            ProjectSprint, ProjectSprint.id == ProjectSprintItem.sprint_id).filter(
                WorkItem.tenant_id == self.user.tenant_id, ProjectSprint.tenant_id == self.user.tenant_id,
                ProjectSprintItem.tenant_id == self.user.tenant_id, ProjectSprint.project_id == WorkItem.project_id,
                or_(ProjectSprintItem.active.is_(True), ProjectSprintItem.completed.is_(True)), condition).cte(recursive=True)
        tree = tree.union(db.session.query(WorkItem.id, WorkItem.project_id).join(tree,
            and_(WorkItem.parent_id == tree.c.id, WorkItem.project_id == tree.c.project_id)).filter(
                WorkItem.tenant_id == self.user.tenant_id))
        return WorkItem.id.in_(db.session.query(tree.c.id))

    def collection(self, field, value, token):
        if not isinstance(value, CollectionFunction):
            raise QueryError('Expected a collection function', token.position)
        name, args = value.name, value.args
        if name in ('opensprints','closedsprints','futuresprints'):
            if field != 'sprint': raise QueryError('Sprint functions require the sprint field',token.position)
            return self.sprint_items(ProjectSprint.state == {'opensprints':'active','closedsprints':'closed','futuresprints':'planned'}[name])
        if name in ('watchedissues', 'votedissues', 'issuehistory'):
            if field != 'key':
                raise QueryError('This function requires the key field', token.position)
            model = {'watchedissues': WorkItemWatcher, 'votedissues': WorkItemVote,
                     'issuehistory': WorkItemView}[name]
            return WorkItem.id.in_(model.query.with_entities(model.work_item_id).filter(
                model.tenant_id == self.user.tenant_id, model.user_id == self.user.id))
        if name not in ('releasedversions', 'unreleasedversions'):
            raise QueryError('This function requires = or !=', token.position)
        if field not in ('fixversion', 'affectsversion'):
            raise QueryError('Version functions require fixVersion or affectsVersion', token.position)
        condition = and_(ProjectVersion.tenant_id == self.user.tenant_id,
                         ProjectVersion.archived.is_(False),
                         ProjectVersion.released.is_(name == 'releasedversions'))
        if args:
            condition = and_(condition, ProjectVersion.project_id.in_(
                Project.query.with_entities(Project.id).filter(Project.tenant_id == self.user.tenant_id,
                    or_(func.lower(Project.key) == args[0].lower(), func.lower(Project.name) == args[0].lower()))))
        relation = WorkItem.fix_versions if field == 'fixversion' else WorkItem.affects_versions
        return relation.any(condition)

    def history_change(self, field, token):
        fields = {'status': 'status', 'priority': 'priority', 'summary': 'title',
                  'description': 'description', 'type': 'item_type', 'parent': 'parent',
                  'start': 'start_date', 'due': 'due_date', 'storypoints': 'story_points',
                  'estimate': 'estimate_minutes', 'remaining': 'remaining_minutes'}
        if field not in fields:
            raise QueryError('CHANGED is not supported for this field', token.position)
        conditions = [WorkItemHistory.tenant_id == self.user.tenant_id,
                      WorkItemHistory.field == fields[field]]
        qualifiers = set()
        while self.peek() and self.peek().text.upper() in ('FROM', 'TO', 'BY', 'BEFORE', 'AFTER', 'DURING') and not self.peek().quoted:
            qualifier = self.pop()
            name = qualifier.text.upper()
            if name in qualifiers:
                raise QueryError('Repeated history qualifier', qualifier.position)
            qualifiers.add(name)
            if name == 'DURING':
                self.require('('); first = self.history_date(self.value(), qualifier)
                self.require(','); last = self.history_date(self.value(), qualifier); self.require(')')
                if first > last: raise QueryError('History interval ends before it starts', qualifier.position)
                conditions.extend((WorkItemHistory.created_at >= first, WorkItemHistory.created_at <= last))
                continue
            value = self.value()
            if name in ('FROM', 'TO'):
                if not isinstance(value, str): raise QueryError('Expected a historical field value', qualifier.position)
                column = WorkItemHistory.old_value if name == 'FROM' else WorkItemHistory.new_value
                conditions.append(func.lower(column) == value.lower())
            elif name == 'BY':
                if isinstance(value, tuple) and value[0] == 'user':
                    conditions.append(WorkItemHistory.actor_id == value[1])
                elif isinstance(value, str):
                    conditions.append(WorkItemHistory.actor_id.in_(User.query.with_entities(User.id).filter(
                        User.tenant_id == self.user.tenant_id,
                        or_(func.lower(User.username) == value.lower(), func.lower(User.name) == value.lower()))))
                else: raise QueryError('Expected a user', qualifier.position)
            else:
                date_value = self.history_date(value, qualifier)
                conditions.append(WorkItemHistory.created_at < date_value if name == 'BEFORE' else WorkItemHistory.created_at > date_value)
        return WorkItem.id.in_(WorkItemHistory.query.with_entities(WorkItemHistory.work_item_id).filter(*conditions))

    def history_date(self, value, token):
        try:
            if isinstance(value, str):
                relative = re.fullmatch(r'([+-]?\d{1,5})([dhwm])', value)
                if relative:
                    value = self.clock + timedelta(minutes=int(relative[1])*{'d':1440,'h':60,'w':10080,'m':1}[relative[2]])
                else: value = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if not isinstance(value, datetime): raise ValueError()
            return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc))
        except (ValueError, TypeError, OverflowError):
            raise QueryError('Expected an ISO timestamp, relative duration or date function', token.position) from None

    def clause(self):
        token=self.pop(); field=self.field(token); op=self.pop()
        operator=op.text.upper()
        if operator == 'CHANGED' and not op.quoted:
            return self.history_change(field, token)
        if operator=='IS' and not op.quoted:
            negate=bool(self.peek('NOT'))
            if negate: self.pop()
            self.require('EMPTY')
            present=self.present(field)
            return present if negate else not_(present)
        if operator=='NOT' and not op.quoted:
            self.require('IN'); operator='NOT IN'
        if operator in ('IN','NOT IN') and not op.quoted:
            if not self.peek('('):
                matches = self.collection(field, self.value(), token)
                return and_(self.present(field), not_(matches)) if operator == 'NOT IN' else matches
            self.require('('); values=[self.value()]
            while self.peek(','):
                self.pop(); values.append(self.value())
                if len(values)>100: raise QueryError('List is too long',token.position)
            self.require(')')
            matches=or_(*(self.collection(field,value,token) if isinstance(value,CollectionFunction) else self.match(field,'=',value,token) for value in values))
            return and_(self.present(field),not_(matches)) if operator=='NOT IN' else matches
        if op.quoted or operator not in ('=','!=','>','>=','<','<=','~','!~'):
            raise QueryError('Unsupported operator',op.position)
        return self.match(field,operator,self.value(),token)

    def value(self):
        token=self.pop()
        if not token.quoted and token.text.upper() in ('AND','OR','NOT','ORDER','EMPTY','NULL','(',')',',','=','!=','>','>=','<','<=','~','!~'):
            raise QueryError('Expected a value; quote reserved words',token.position)
        if not token.quoted and self.peek('('):
            self.pop()
            args = []
            if not self.peek(')'):
                argument = self.pop()
                if not argument.quoted and argument.text in ('(', ')', ',', '=', '!='):
                    raise QueryError('Expected a function argument', argument.position)
                args.append(argument.text)
            self.require(')')
            name = token.text.lower()
            if name == 'currentuser':
                if args: raise QueryError('currentUser takes no arguments', token.position)
                return ('user', self.user.id)
            if name in ('watchedissues', 'votedissues', 'issuehistory', 'releasedversions', 'unreleasedversions', 'latestreleasedversion', 'earliestunreleasedversion', 'opensprints', 'closedsprints', 'futuresprints'):
                if name in ('latestreleasedversion', 'earliestunreleasedversion') and not args:
                    raise QueryError('A project key or name is required', token.position)
                if args and name not in ('releasedversions', 'unreleasedversions', 'latestreleasedversion', 'earliestunreleasedversion'):
                    raise QueryError('This function takes no arguments', token.position)
                if args and (not args[0].strip() or len(args[0]) > 160):
                    raise QueryError('Expected a project key or name', token.position)
                return CollectionFunction(name, tuple(args))
            return calendar_function(name, args, self.clock, token.position)
        return token.text

    def present(self, field):
        if field=='sprint': return self.sprint_items(true())
        if field=='assignee': return WorkItem.assignees.any()
        if field=='labels': return WorkItem.labels.any()
        if field in ('component','fixversion','affectsversion'):
            return {'component':WorkItem.components,'fixversion':WorkItem.fix_versions,'affectsversion':WorkItem.affects_versions}[field].any()
        if field=='parent': return WorkItem.parent_id.isnot(None)
        if field=='resolution': return WorkItem.resolution_id.isnot(None)
        if field=='reporter': return WorkItem.reporter_id.isnot(None)
        column=COLUMNS.get(field)
        if column is not None:
            return and_(column.isnot(None),column!='') if field in ('summary','description') else column.isnot(None)
        if field=='text': return or_(WorkItem.title!='',WorkItem.description!='')
        return true()

    def match(self, field, operator, value, token):
        if isinstance(value, CollectionFunction):
            if value.name not in ('latestreleasedversion', 'earliestunreleasedversion'):
                raise QueryError('Collection functions require IN or NOT IN', token.position)
            if field not in ('fixversion', 'affectsversion') or operator not in ('=', '!='):
                raise QueryError('This version function requires a version field and = or !=', token.position)
            released = value.name == 'latestreleasedversion'
            projects = service.visible_projects(self.user).with_entities(Project.id).filter(
                or_(func.lower(Project.key) == value.args[0].lower(), func.lower(Project.name) == value.args[0].lower()))
            version = ProjectVersion.query.with_entities(ProjectVersion.id).filter(
                ProjectVersion.tenant_id == self.user.tenant_id, ProjectVersion.project_id.in_(projects),
                ProjectVersion.archived.is_(False), ProjectVersion.released.is_(released)).order_by(
                    ProjectVersion.position.desc() if released else ProjectVersion.position.asc(),
                    ProjectVersion.id.desc() if released else ProjectVersion.id.asc()).limit(1).scalar_subquery()
            relation = WorkItem.fix_versions if field == 'fixversion' else WorkItem.affects_versions
            matches = relation.any(ProjectVersion.id == version)
            return and_(self.present(field), not_(matches)) if operator == '!=' else matches
        negative=operator in ('!=','!~')
        positive='=' if operator=='!=' else '~' if operator=='!~' else operator
        if positive in ('>','>=','<','<=') and field not in DATES|NUMBERS:
            raise QueryError('Ordering comparisons require a date or number',token.position)
        if positive=='~' and field not in ('summary','description','text'):
            raise QueryError('Text matching requires summary, description or text',token.position)
        if field in DATES:
            if isinstance(value,str):
                relative=re.fullmatch(r'([+-]?\d{1,5})([dhwm])',value)
                try:
                    if relative:
                        amount=int(relative[1]); unit={'d':1440,'h':60,'w':10080,'m':1}[relative[2]]
                        value=self.clock+timedelta(minutes=amount*unit)
                    else:
                        value=datetime.fromisoformat(value.replace('Z','+00:00'))
                        if value.tzinfo is None: value=value.replace(tzinfo=timezone.utc)
                except (ValueError,OverflowError):
                    raise QueryError('Expected an ISO date or relative duration',token.position) from None
            if not isinstance(value,(date,datetime)):
                raise QueryError('Expected a date',token.position)
            if isinstance(value,datetime):
                value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
                if field in ('start','due'): value=value.date()
        elif field in NUMBERS:
            try:
                value=float(value)
                if not math.isfinite(value): raise ValueError()
            except (ValueError,TypeError,OverflowError):
                raise QueryError('Expected a finite number',token.position) from None
        elif field=='flagged':
            if str(value).lower() not in ('true','false'): raise QueryError('Expected true or false',token.position)
            value=str(value).lower()=='true'
        elif isinstance(value,datetime) or isinstance(value,tuple) and field not in ('assignee','reporter'):
            raise QueryError('Function is not supported for this field',token.position)
        if field in COLUMNS:
            col=COLUMNS[field]
            if positive=='~':
                pattern=str(value).replace('\\','\\\\').replace('%','\\%').replace('_','\\_').replace('*','%').replace('?','_')
                match=col.ilike('%'+pattern+'%',escape='\\')
            elif field in DATES|NUMBERS or field=='flagged':
                match={'=':lambda:col==value,'>':lambda:col>value,'>=':lambda:col>=value,
                       '<':lambda:col<value,'<=':lambda:col<=value}[positive]()
            else: match=func.lower(col)==str(value).lower()
        elif field=='text':
            match=or_(self.match('summary',positive,value,token),self.match('description',positive,value,token))
        elif field=='sprint':
            condition = ProjectSprint.id==int(value) if str(value).isdigit() else func.lower(ProjectSprint.name)==str(value).lower()
            match=self.sprint_items(condition)
        elif field=='project':
            match=WorkItem.project.has(or_(func.lower(Project.key)==str(value).lower(),func.lower(Project.name)==str(value).lower()))
        elif field=='key':
            parsed=service.parse_item_key(str(value))
            match=and_(WorkItem.project.has(Project.key==parsed[0]),WorkItem.number==parsed[1]) if parsed else false()
        elif field in ('status','category'):
            col=ProjectStatus.name if field=='status' else ProjectStatus.category
            match=WorkItem.status.has(func.lower(col)==str(value).lower())
        elif field=='priority':
            match=func.lower(WorkItem.priority)==str(value).lower()
        elif field in ('assignee','reporter'):
            condition=(User.id==value[1] if isinstance(value,tuple) else or_(func.lower(User.username)==str(value).lower(),func.lower(User.name)==str(value).lower()))
            match=WorkItem.assignees.any(condition) if field=='assignee' else WorkItem.reporter.has(condition)
        elif field=='labels': match=WorkItem.labels.any(func.lower(WorkItemLabel.label)==str(value).lower())
        elif field=='parent':
            parsed=service.parse_item_key(str(value))
            match=WorkItem.parent.has(and_(WorkItem.number==parsed[1],WorkItem.project.has(Project.key==parsed[0]))) if parsed else false()
        elif field=='resolution': match=WorkItem.resolution.has(func.lower(WorkItemResolution.name)==str(value).lower())
        elif field=='component': match=WorkItem.components.any(func.lower(ProjectComponent.name)==str(value).lower())
        else:
            rel=WorkItem.fix_versions if field=='fixversion' else WorkItem.affects_versions
            match=rel.any(func.lower(ProjectVersion.name)==str(value).lower())
        return and_(self.present(field),not_(match)) if negative else match

    def order_column(self, field, token):
        if field in COLUMNS: return COLUMNS[field]
        if field=='key': return WorkItem.number
        if field=='priority': return case({value:i for i,value in enumerate(PRIORITIES)},value=WorkItem.priority,else_=99)
        raise QueryError('Sorting is not supported for this field',token.position)


def search(user, source):
    """Permissions are ANDed outside the complete user expression, including OR."""
    try:
        if not user.is_authenticated or not user.active:
            raise QueryError('An active signed-in user is required')
        predicate,ordering=Parser(source,user).parse()
        visible=service.visible_projects(user).with_entities(Project.id)
        return WorkItem.query.filter(WorkItem.tenant_id==user.tenant_id,WorkItem.project_id.in_(visible),predicate).options(
            joinedload(WorkItem.project),joinedload(WorkItem.status)).order_by(*ordering)
    except QueryError:
        raise
    except Exception:
        current_app.logger.error('Project search failed for tenant %s',user.tenant_id)
        raise
