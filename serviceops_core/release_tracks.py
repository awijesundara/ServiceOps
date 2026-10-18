"""Deployment-time gate for continuous, bundled and isolated preview tracks."""
import calendar
import json
import logging
import re
from datetime import datetime,timezone
from zoneinfo import ZoneInfo

from sqlalchemy import inspect,text

KEY='PREMIUM_PLATFORM_POLICY'
IMAGE=re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$')


def read(engine):
    try:
        with engine.connect() as connection:
            if 'platform_setting' not in inspect(connection).get_table_names():return None
            raw=connection.execute(text('SELECT value FROM platform_setting WHERE key=:key'),dict(key=KEY)).scalar()
            return json.loads(raw) if raw else None
    except Exception as error:
        logging.getLogger(__name__).error('Release policy read failed: %s',type(error).__name__)
        raise RuntimeError('Release policy could not be verified') from None


def check(engine,image,environment='production',override_reason='',clock=None):
    try:
        policy=read(engine)
        if environment=='sandbox':return 'preview'
        if override_reason:
            if len(override_reason.strip())<12:raise ValueError('An operator override needs a meaningful reason of at least 12 characters')
            logging.getLogger(__name__).warning('Release track overridden by installation operator')
            return 'operator_override'
        if not policy or policy.get('track','continuous')=='continuous':return 'continuous'
        if not IMAGE.fullmatch(image or ''):raise ValueError('A bundled deployment requires the immutable image reference')
        if image==policy.get('last_approved_image'):return 'approved_retry'
        current=(clock or datetime.now(timezone.utc)).astimezone(ZoneInfo(policy.get('timezone','UTC'))).date()
        date=datetime.strptime(policy['next_release'],'%Y-%m-%d').date()
        if current<date:raise ValueError('The bundled release window has not opened')
        return 'bundled'
    except (ValueError,KeyError) as error:
        logging.getLogger(__name__).warning('Release track blocked deployment: %s',type(error).__name__)
        raise RuntimeError(str(error)) from None
    except Exception as error:
        logging.getLogger(__name__).error('Release track verification failed: %s',type(error).__name__)
        raise RuntimeError('Release track could not be verified') from None


def record(engine,image,environment='production',clock=None):
    try:
        if environment=='sandbox' or not IMAGE.fullmatch(image or ''):return
        with engine.begin() as connection:
            statement='SELECT value FROM platform_setting WHERE key=:key'+(' FOR UPDATE' if connection.dialect.name=='postgresql' else '')
            raw=connection.execute(text(statement),dict(key=KEY)).scalar()
            policy=json.loads(raw) if raw else dict(track='continuous',timezone='UTC',next_release=None,ip_networks=[])
            if image==policy.get('last_approved_image'):return
            if policy.get('track')=='bundled':
                old=datetime.strptime(policy['next_release'],'%Y-%m-%d').date()
                current=(clock or datetime.now(timezone.utc)).astimezone(ZoneInfo(policy.get('timezone','UTC'))).date()
                year=current.year+(current.month==12);month=current.month%12+1
                policy['next_release']=old.replace(year=year,month=month,day=min(old.day,calendar.monthrange(year,month)[1])).isoformat()
            policy['revision']=policy.get('revision',0)+1
            policy['last_approved_image']=image;policy['last_migration_at']=(clock or datetime.now(timezone.utc)).isoformat()
            values=dict(key=KEY,value=json.dumps(policy),updated_at=datetime.now(timezone.utc))
            if raw:connection.execute(text('UPDATE platform_setting SET value=:value,updated_at=:updated_at WHERE key=:key'),values)
            else:connection.execute(text('INSERT INTO platform_setting (key,value,tenant_id,encrypted,updated_at) VALUES (:key,:value,1,false,:updated_at)'),values)
    except Exception as error:
        logging.getLogger(__name__).error('Release approval record failed: %s',type(error).__name__)
        raise RuntimeError('Migration succeeded but release approval could not be recorded') from None
