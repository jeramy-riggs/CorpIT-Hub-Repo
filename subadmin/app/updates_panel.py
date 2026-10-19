"""Server updates (System > Updates): weekly patching for itam and the corpit A/B pair.

The console never runs apt, ssh or sudo itself - on the dev server the egress
guard refuses all three, and subadmin has no sudo anyway. Every request goes to
the root corpit-updates service over its socket, which accepts a fixed set of
operations, checks the operator against its own allowlist (published from
Settings > Server updates) and records each job step by step.

Where that service is not installed - every host except itam - the socket is
absent, this tab is not rendered and the routes answer 404. Nothing here can act
on a host that does not run the service.
"""
import json
import os
import re
import socket

from flask import abort, jsonify, request, session

SOCKET = '/run/corpit-updates/updates.sock'
ACTIONS = ('refresh', 'apply-itam', 'reboot-itam', 'apply-standby', 'switch-reboot')
# Reboots are typed, not clicked: the phrase is checked here as well as in the page.
CONFIRM = {'reboot-itam': 'REBOOT ITAM', 'switch-reboot': 'SWITCH REBOOT'}
JOB_RE = re.compile(r'u-\d{8}-\d{6}-[0-9a-f]{4}', re.ASCII)
MAX_REPLY = 4 * 1024 * 1024


class Unavailable(Exception):
    pass


def available():
    """True only where the root updates service has its socket (itam)."""
    try:
        return os.path.exists(SOCKET)
    except OSError:
        return False


def call(req, timeout=40):
    """One request, one newline-terminated JSON answer. Raises Unavailable on transport failure."""
    if not available():
        raise Unavailable('the updates service is not installed on this host')
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(SOCKET)
        s.sendall((json.dumps(req, separators=(',', ':')) + '\n').encode())
        buf = b''
        while not buf.endswith(b'\n'):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_REPLY:
                raise Unavailable('the updates service answer was too large')
    except (OSError, socket.timeout) as exc:
        raise Unavailable('the updates service did not answer (%s)' % exc.__class__.__name__)
    finally:
        s.close()
    try:
        answer = json.loads(buf)
    except ValueError:
        raise Unavailable('the updates service answer was not readable')
    if not isinstance(answer, dict) or not isinstance(answer.get('ok'), bool):
        raise Unavailable('the updates service answer was not readable')
    return answer


def publish_policy(actor, values):
    """Settings > Server updates -> the service. Returns an error string or None; a host without the service skips it."""
    if not available():
        return None
    policy = {'allowedActors': list(values.get('allowed_actors') or []),
              'overdueDays': values.get('overdue_days'),
              'switchBackDefault': values.get('switch_back_default'),
              'checkHours': values.get('check_hours')}
    try:
        answer = call({'op': 'policy', 'actor': actor or '-', 'policy': policy})
    except Unavailable as exc:
        return str(exc)
    return None if answer['ok'] else (answer.get('error') or 'refused')


def _actor():
    return str(session.get('user') or '').strip().lower()


def _reply(payload, status=200):
    response = jsonify(payload)
    response.status_code = status
    response.headers['Cache-Control'] = 'no-store, private'
    return response


def register(app, owner_required, audit, check_csrf):
    app.jinja_env.globals['updates_available'] = available

    def gate():
        if not available():
            abort(404)

    @app.route('/system/updates/summary')
    @owner_required
    def updates_summary():
        gate()
        try:
            answer = call({'op': 'summary'})
        except Unavailable as exc:
            return _reply(dict(ok=False, error=str(exc)), 503)
        if not answer['ok']:
            return _reply(dict(ok=False, error=answer.get('error') or 'refused'), 502)
        data = answer['result']
        me = _actor()
        allowed = me in [a.lower() for a in (data.get('policy') or {}).get('allowedActors') or []]
        return _reply(dict(ok=True, data=data,
                           me=dict(actor=me, allowed=allowed,
                                   canSwitch=allowed and me == str(data.get('controllerActor') or '').lower())))

    @app.route('/system/updates/job/<job_id>')
    @owner_required
    def updates_job(job_id):
        gate()
        if not JOB_RE.fullmatch(job_id):
            return _reply(dict(ok=False, error='invalid job id'), 400)
        try:
            answer = call({'op': 'job', 'jobId': job_id})
        except Unavailable as exc:
            return _reply(dict(ok=False, error=str(exc)), 503)
        if not answer['ok']:
            return _reply(dict(ok=False, error=answer.get('error') or 'refused'), 404)
        return _reply(dict(ok=True, job=answer['result']['job']))

    @app.route('/system/updates/start', methods=['POST'])
    @owner_required
    def updates_start():
        gate()
        check_csrf()
        action = request.form.get('action', '')
        reason = request.form.get('reason', '').strip()
        switch_back = request.form.get('switch_back') == '1'
        if action not in ACTIONS:
            return _reply(dict(ok=False, error='unknown action'), 400)
        if action in CONFIRM and request.form.get('confirm', '').strip() != CONFIRM[action]:
            return _reply(dict(ok=False, error='type %s to confirm' % CONFIRM[action]), 400)
        actor = _actor()
        try:
            audit('updates-start-requested', 'action=%s switch_back=%s reason=%s'
                  % (action, switch_back if action == 'switch-reboot' else '-', reason[:200]))
        except Exception:
            return _reply(dict(ok=False, error='The audit log could not record this request. Nothing was started.'), 503)
        try:
            answer = call({'op': 'start', 'actor': actor, 'action': action, 'reason': reason,
                           'switchBack': switch_back})
        except Unavailable as exc:
            audit('updates-start-failed', '%s: %s' % (action, exc))
            return _reply(dict(ok=False, error=str(exc)), 503)
        if not answer['ok']:
            audit('updates-start-refused', '%s: %s' % (action, answer.get('error')))
            return _reply(dict(ok=False, error=answer.get('error') or 'refused'), 409)
        job = answer['result']['job']
        audit('updates-start', '%s %s' % (job.get('jobId'), action))
        return _reply(dict(ok=True, job=job))

    @app.route('/system/updates/cancel', methods=['POST'])
    @owner_required
    def updates_cancel():
        gate()
        check_csrf()
        job_id = request.form.get('job_id', '')
        if not JOB_RE.fullmatch(job_id):
            return _reply(dict(ok=False, error='invalid job id'), 400)
        try:
            answer = call({'op': 'cancel', 'actor': _actor(), 'jobId': job_id})
        except Unavailable as exc:
            return _reply(dict(ok=False, error=str(exc)), 503)
        if not answer['ok']:
            audit('updates-cancel-refused', '%s: %s' % (job_id, answer.get('error')))
            return _reply(dict(ok=False, error=answer.get('error') or 'refused'), 409)
        audit('updates-cancel', job_id)
        return _reply(dict(ok=True, job=answer['result']['job']))
