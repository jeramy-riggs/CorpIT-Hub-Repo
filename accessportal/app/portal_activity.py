"""Minimal metadata federation; never copy comments, signatures or form bodies."""
import re


def route_name(path):
    path = re.sub(r"/requests/[^/]+", "/requests/:id", path)
    path = re.sub(r"/\d+(?=/|$)", "/:id", path)
    return path[:100]


def audit_events(conn, email, since):
    rows = conn.execute('''
      SELECT a.id,a.created_at,a.event,a.actor,a.request_id,
             CASE WHEN lower(a.actor)=? THEN 'Recorded actor' ELSE 'Affected request / acknowledgment' END relation
      FROM audit_log a
      WHERE a.created_at>=? AND (
        lower(a.actor)=? OR a.request_id IN (
          SELECT id FROM requests WHERE json_valid(submitter) AND lower(json_extract(submitter,'$.email'))=?
          UNION SELECT 'ACK-'||id FROM acknowledgments WHERE lower(email)=?
        ))
      ORDER BY a.created_at DESC,a.id DESC LIMIT 501
    ''', (email, since, email, email, email)).fetchall()
    return [{"id": "portal-audit-"+str(r['id']), "ts": r['created_at'],
             "event": r['event'], "summary": r['event'].replace('.', ' '),
             "detail": r['request_id'] or '', "relationship": r['relation'],
             "severity": 'error' if re.search(r'fail|denied|refused|error|unroutable', r['event'], re.I) else 'info'} for r in rows]
