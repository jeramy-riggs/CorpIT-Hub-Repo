"""Owner-only Subadmin activity metadata with mandatory lookup auditing.

Sources (settingsfold W6, 2026-10-12). Each one reports id, label, state
(available/unavailable), count, truncated and a note; data.source stays the
Subadmin audit so pages that read only that keep working, and data.sources
lists every source:
  subadmin   Subadmin audit   SQLite audit table, exact lower("user") match.
  launchpad  Launch pad       devrel release log (JSONL), exact "by" match.
  backup     Backup console   bkp-console audit log. The subadmin service cannot
                              read it (root:bkpui 0600); shown as unavailable and
                              marked fetched_by="browser": the Health page reads
                              this source from bkp-console itself (/bkp-api/activity,
                              W6 follow-up d) and drops this placeholder.
A source whose store directory is absent on this host is left out. Matching is
by exact email only: display names and phrases such as "x for a@b" are not
matched, because that would be inference. Free-text fields (note, reason, why,
error) and changed values are never returned, only event names, the site,
the release id and changed field names.
"""
import collections
import json
import os
import re
from datetime import datetime, timedelta, timezone
from flask import request, jsonify

LIMIT = 500
LAUNCHPAD_DIR = '/var/lib/dev-release'
LAUNCHPAD_LOG = '/var/lib/dev-release/release.log'
BACKUP_DIR = '/var/lib/bkp'
BACKUP_AUDIT = '/var/lib/bkp/audit.jsonl'
ERROR_EVENT = re.compile(r'denied|fail|refused')


def _subadmin(db, email, since):
    rows = db().execute('SELECT id,ts,action FROM audit WHERE lower("user")=? AND ts>=? ORDER BY ts DESC,id DESC LIMIT 501', (email, since)).fetchall()
    events = [dict(id='subadmin-'+str(r['id']), ts=r['ts'], event=r['action'],
                   summary=r['action'].replace('-', ' '), source='subadmin', source_label='Subadmin audit',
                   relationship='Recorded actor', severity='error' if re.search('denied|failed|refused',r['action']) else 'info') for r in rows[:500]]
    return events, dict(id='subadmin', label='Subadmin audit', state='available', count=len(events), truncated=len(rows)>500, note='Exact actor email match. Local-account aliases and unstructured targets are not inferred; sensitive audit details are excluded.')


def _launchpad(email, since):
    label = 'Launch pad'
    try:
        fh = open(LAUNCHPAD_LOG, encoding='utf-8', errors='replace')
    except FileNotFoundError:
        return [], dict(id='launchpad', label=label, state='unavailable', count=None, truncated=False,
                        note='No launch pad release log on this host (%s).' % LAUNCHPAD_LOG)
    except OSError as e:
        return [], dict(id='launchpad', label=label, state='unavailable', count=None, truncated=False,
                        note='The launch pad release log could not be read by this service (%s).' % (e.strerror or type(e).__name__))
    keep, total, bad = collections.deque(maxlen=LIMIT), 0, 0
    try:
        with fh:
            for n, line in enumerate(fh, 1):
                if '"by"' not in line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                if not isinstance(r, dict):
                    bad += 1
                    continue
                by, ts = r.get('by'), r.get('ts')
                if not isinstance(by, str) or by.strip().lower() != email:
                    continue
                if not isinstance(ts, str) or len(ts) < 19 or ts[:19] < since:
                    continue
                total += 1
                keep.append((n, r))
    except OSError as e:
        return [], dict(id='launchpad', label=label, state='unavailable', count=None, truncated=False,
                        note='The launch pad release log could not be read to the end (%s).' % (e.strerror or type(e).__name__))
    events = []
    for n, r in sorted(keep, key=lambda x: (x[1]['ts'][:19], x[0]), reverse=True):
        ev = str(r.get('event') or 'event')[:64]
        site = r.get('site') if isinstance(r.get('site'), str) else ''
        detail = []
        rel = r.get('rel') if isinstance(r.get('rel'), str) else ''
        if rel:
            detail.append('Release ' + rel[:80])
        if isinstance(r.get('changed'), dict) and r['changed']:
            detail.append('Changed: ' + ', '.join(sorted(str(k)[:40] for k in r['changed'])[:20]))
        sev = 'error' if (ERROR_EVENT.search(ev) or r.get('ok') is False) else ('warn' if r.get('sev') == 'warn' else 'info')
        events.append(dict(id='launchpad-%d' % n, ts=r['ts'], event=ev,
                           summary=ev.replace('-', ' ').replace('_', ' ') + (' · ' + site[:80] if site else ''),
                           detail='; '.join(detail), source='launchpad', source_label=label,
                           relationship='Recorded actor', severity=sev))
    note = ('Exact match on the release log "by" email. Entries signed with a name or phrase instead of an email '
            'are not matched; notes, reasons, errors and changed values are excluded.')
    if bad:
        note += ' %d unreadable line(s) were skipped.' % bad
    return events, dict(id='launchpad', label=label, state='available', count=len(events), truncated=total > LIMIT, note=note)


def _backup():
    # W6 stopped at the access check: the subadmin service has no read access to the
    # bkp-console audit log, and none was added. No reader is built for it.
    label = 'Backup console'
    if os.access(BACKUP_AUDIT, os.R_OK):
        note = ('The backup console audit log is readable by this service, but no reader has been built for it yet, '
                'so backup console changes are not included.')
    else:
        note = ('Not readable by this service: the backup console audit log is limited to root and the bkpui group, '
                'and access was not widened. Backup console changes are not included in this lookup.')
    note += (' The Health page reads backup console changes from the backup console itself '
             '(/bkp-api/activity) and shows that result in place of this entry.')
    return [], dict(id='backup', label=label, state='unavailable', count=None, truncated=False, note=note,
                    fetched_by='browser')


def register(app, owner_required, db, audit):
    @app.route('/health/activity/person')
    @owner_required
    def user_activity_person():
        email = str(request.args.get('email') or '').strip().lower()
        if not re.fullmatch(r'[^\s@<>"\x27(),;:]{1,64}@[a-z0-9.-]{1,190}\.[a-z]{2,}', email):
            return jsonify(ok=False, error='Enter a full email address or UPN.'), 400
        try:
            days = max(1, min(90, int(request.args.get('days') or 30)))
        except ValueError:
            days = 30
        try:
            audit('user-activity-lookup', 'subject=%s days=%s' % (email, days))
        except Exception:
            return jsonify(ok=False, error='The audit service could not record this lookup. No personal activity was read.'), 503
        since = (datetime.now(timezone.utc)-timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S')
        events, primary = _subadmin(db, email, since)
        sources = [primary]
        if os.path.isdir(LAUNCHPAD_DIR):
            ev, src = _launchpad(email, since)
            events += ev
            sources.append(src)
        if os.path.isdir(BACKUP_DIR):
            ev, src = _backup()
            events += ev
            sources.append(src)
        response = jsonify(ok=True, data=dict(events=events, source=primary, sources=sources))
        response.headers['Cache-Control'] = 'no-store, private'
        return response
