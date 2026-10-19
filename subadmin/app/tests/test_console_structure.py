#!/usr/bin/env python3
"""Structural checks on the rendered console: balanced tags, no nested forms,
every action a real endpoint, and no control that cannot act."""
import re
import sys
import time
from html.parser import HTMLParser

sys.path.insert(0, "/opt/subdomain-admin")
import app as A  # noqa: E402

c = A.app.test_client()
with c.session_transaction() as s:
    s["user"] = "jriggs@auction.com"
    s["auth_at"] = int(time.time())
    s["sso"] = {"user": "jriggs@auction.com", "name": "Jeramy Keith",
                "role": "platform-owner", "groups": ["saas-ith-sa"],
                "can_write_prod": True, "auth": "entra"}
body = c.get("/console").get_data(as_text=True)

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}
FAIL = []


class Check(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.form_depth = 0
        self.problems = []
        self.labels = 0
        self.ids = set()
        self.dupe_ids = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if d.get("id"):
            if d["id"] in self.ids:
                self.dupe_ids.append(d["id"])
            self.ids.add(d["id"])
        if tag == "form":
            self.form_depth += 1
            if self.form_depth > 1:
                self.problems.append("nested <form> at line %d" % self.getpos()[0])
        if tag == "label":
            self.labels += 1
        if tag not in VOID:
            self.stack.append((tag, self.getpos()[0]))

    def handle_startendtag(self, tag, attrs):
        pass

    def handle_endtag(self, tag):
        if tag == "form":
            self.form_depth -= 1
        if tag in VOID:
            return
        if not self.stack:
            self.problems.append("stray </%s> at line %d" % (tag, self.getpos()[0]))
            return
        if self.stack[-1][0] == tag:
            self.stack.pop()
        else:
            for i in range(len(self.stack) - 1, -1, -1):
                if self.stack[i][0] == tag:
                    unclosed = [t for t, _ in self.stack[i + 1:]]
                    self.problems.append(
                        "</%s> at line %d closes over unclosed %s"
                        % (tag, self.getpos()[0], unclosed))
                    del self.stack[i:]
                    break
            else:
                self.problems.append("unmatched </%s> line %d" % (tag, self.getpos()[0]))


p = Check()
p.feed(body)


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + (("  -- " + detail) if not cond else ""))
    if not cond:
        FAIL.append(name)


check("tags balanced", not p.stack and not p.problems,
      str(p.problems[:5]) + " unclosed=" + str([t for t, _ in p.stack[:5]]))
check("no duplicate element ids", not p.dupe_ids, str(sorted(set(p.dupe_ids))[:8]))

# Every form action must resolve to a real endpoint that accepts POST.
actions = sorted(set(re.findall(r'<form[^>]*action="([^"]+)"', body)))
adapter = A.app.url_map.bind("subadmin.nrpi.local")
bad = []
for a in actions:
    try:
        adapter.match(a.split("#")[0], method="POST")
    except Exception as e:
        bad.append("%s (%s)" % (a, type(e).__name__))
check("every form action is a real POST route (%d)" % len(actions), not bad, str(bad))

# A control that cannot act must not be present as if it could.
check("no prototype data-needs-server attributes left on elements",
      not re.search(r'<[a-z]+[^>]*\sdata-needs-server[\s>]', body))
check("no 'Layout prototype' badge", "Layout prototype" not in body)
check("operations queue and evidence pane are present",
      'id="ops-list"' in body and 'id="ops-evidence"' in body and
      'href="/operations/workspace"' in body)
check("approved attention registry is the default Overview",
      body.index('data-view="overview"') < body.index('id="ops-board"') <
      body.index('data-view="operations"'))
check("unknown operations data is never called healthy",
      "It is not being treated as healthy while evidence is unavailable" in body)
nav_buttons = re.findall(r'<button class="nav-item"[^>]*>', body)
check("compact rail keeps names and hover labels",
      len(nav_buttons) == 8 and all('aria-label=' in b and 'title=' in b for b in nav_buttons),
      str(nav_buttons))
ops_list_match = re.search(r'<div class="ops-list".*?</div>\s*</section>', body, re.S)
ops_list = ops_list_match.group(0) if ops_list_match else ""
check("finding rows use ordinary button semantics",
      bool(ops_list) and 'role="listbox"' not in ops_list and
      'role="option"' not in ops_list and 'class="ops-record' in ops_list and
      'aria-pressed=' in ops_list)
check("operations handoffs target real workspace registers",
      'href="/operations/workspace#findings"' in body)
check("directory exposes an explicit one-click mobile rollout",
      "Everyone with a cellphone, on every cellphone" in body and
      re.search(r'<form[^>]+action="/gal/lists/[^"/]+/mobile-rollout"', body) is not None and
      "Personal contacts are never touched" in body and
      "successful apply" in body)

with open("/opt/subdomain-admin/private/console.js", encoding="utf-8") as fh:
    console_js = fh.read()
check("a failed finding read clears stale detail fields",
      all(marker in console_js for marker in (
          "Previously selected details have been cleared",
          "text('ops-cause', 'Unavailable while the finding store cannot be read.')",
          "text('ops-impact', 'Unknown. Do not infer an all-clear from this failed read.')",
          "text('ops-owner', 'Owner unavailable')")))

# Every submit button lives inside a form.
outside = re.findall(r'<button[^>]*type="submit"', body)
check("submit buttons exist (%d)" % len(outside), len(outside) > 10)

# CSRF on every form.
forms = re.findall(r"<form\b.*?</form>", body, re.S)
# A method="dialog" form with no action closes its <dialog> in the browser and never reaches the server (the updates and web watch
# panels post by fetch with the csrf field in the body, and their routes call check_csrf()), so it has no token to carry. 10-13
def _dialog_only(f):
    tag = re.match(r"<form\b[^>]*>", f).group(0)
    return 'method="dialog"' in tag and "action=" not in tag
missing = [f[:90] for f in forms if 'name="csrf"' not in f and not _dialog_only(f)]
check("every form carries a CSRF token (%d forms)" % len(forms), not missing, str(missing))

# Every _back value is the console's own path.
backs = sorted(set(re.findall(r'name="_back" value="([^"]*)"', body)))
check("every _back is a console anchor", all(re.match(r"^/console(#[a-z]+)?$", b) for b in backs),
      str(backs))

print("\n%s (%d failures)" % ("STRUCTURE OK" if not FAIL else "FAILURES", len(FAIL)))
sys.exit(1 if FAIL else 0)
