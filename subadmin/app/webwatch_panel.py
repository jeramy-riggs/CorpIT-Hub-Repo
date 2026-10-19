"""Prod web watch (System > Web watch): is prod corpit web being served, and the one fix for 10-13.

On 10-13 a failed fence device (fence-A) made A's readiness check answer 503 and the NLB
had no target for 4 h. This tab shows what the HA monitor on itam sees - each node's
answer to the NLB check, both fence devices, open HA alerts and whether their mail went
out - and offers "Clear fence failure", which is `crm_resource --cleanup` for that one
device and nothing else.

The console never runs ssh, sudo or crm itself (the dev egress guard refuses them, and
subadmin has no sudo). Every request goes to the root corpit-webwatch service over its
socket; that service checks the operator against its own allowlist (published from
Settings > Prod web watch) and reaches A/B only through a forced-command wrapper. Where
the service is not installed - every host except itam - the socket is absent, this tab
is not rendered and the routes answer 404.
"""
import json
import os
import socket

from flask import abort, jsonify, request, session

SOCKET = '/run/corpit-webwatch/webwatch.sock'
RESOURCES = ('fence-A', 'fence-B')
MAX_REPLY = 2 * 1024 * 1024


class Unavailable(Exception):
    pass


def available():
    """True only where the root web watch service has its socket (itam)."""
    try:
        return os.path.exists(SOCKET)
    except OSError:
        return False


def confirm_phrase(resource):
    return 'CLEAR ' + resource


def call(req, timeout=40):
    """One request, one newline-terminated JSON answer. Raises Unavailable on transport failure."""
    if not available():
        raise Unavailable('the web watch service is not installed on this host')
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
                raise Unavailable('the web watch service answer was too large')
    except (OSError, socket.timeout) as exc:
        raise Unavailable('the web watch service did not answer (%s)' % exc.__class__.__name__)
    finally:
        s.close()
    try:
        answer = json.loads(buf)
    except ValueError:
        raise Unavailable('the web watch service answer was not readable')
    if not isinstance(answer, dict) or not isinstance(answer.get('ok'), bool):
        raise Unavailable('the web watch service answer was not readable')
    return answer


def publish_policy(actor, values):
    """Settings > Prod web watch -> the service. Returns an error string or None; a host without the service skips it."""
    if not available():
        return None
    policy = {'allowedActors': list(values.get('allowed_actors') or []),
              'repeatCriticalMinutes': values.get('repeat_critical_minutes')}
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
    app.jinja_env.globals['webwatch_available'] = available

    def gate():
        if not available():
            abort(404)

    @app.route('/system/webwatch/status')
    @owner_required
    def webwatch_status():
        gate()
        try:
            answer = call({'op': 'status'})
        except Unavailable as exc:
            return _reply(dict(ok=False, error=str(exc)), 503)
        if not answer['ok']:
            return _reply(dict(ok=False, error=answer.get('error') or 'refused'), 502)
        data = answer['result']
        me = _actor()
        allowed = me in [a.lower() for a in (data.get('policy') or {}).get('allowedActors') or []]
        return _reply(dict(ok=True, data=data, me=dict(actor=me, allowed=allowed)))

    @app.route('/system/webwatch/clear', methods=['POST'])
    @owner_required
    def webwatch_clear():
        gate()
        check_csrf()
        resource = request.form.get('resource', '')
        reason = request.form.get('reason', '').strip()
        if resource not in RESOURCES:
            return _reply(dict(ok=False, error='only fence-A or fence-B can be cleared here'), 400)
        if request.form.get('confirm', '').strip() != confirm_phrase(resource):
            return _reply(dict(ok=False, error='type %s to confirm' % confirm_phrase(resource)), 400)
        if not 3 <= len(reason) <= 500:
            return _reply(dict(ok=False, error='give a reason, 3-500 characters'), 400)
        try:
            audit('webwatch-clear-requested', 'resource=%s reason=%s' % (resource, reason[:200]))
        except Exception:
            return _reply(dict(ok=False, error='The audit log could not record this request. Nothing was cleared.'), 503)
        try:
            answer = call({'op': 'clear-fence', 'actor': _actor(), 'resource': resource, 'reason': reason})
        except Unavailable as exc:
            audit('webwatch-clear-failed', '%s: %s' % (resource, exc))
            return _reply(dict(ok=False, error=str(exc)), 503)
        if not answer['ok']:
            audit('webwatch-clear-refused', '%s: %s' % (resource, answer.get('error')))
            return _reply(dict(ok=False, error=answer.get('error') or 'refused'), 409)
        clear = answer['result']['clear']
        audit('webwatch-clear-started', '%s %s' % (clear.get('id'), resource))
        return _reply(dict(ok=True, clear=clear))
