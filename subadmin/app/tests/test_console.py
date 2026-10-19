#!/usr/bin/env python3
"""Render the console offline, before the live socket ever sees it.

Uses the app's own test client so a broken template or a missing context key
fails here rather than in front of whoever loads the page next.
"""
import re
import sys
import time

sys.path.insert(0, "/opt/subdomain-admin")
import app as A  # noqa: E402

FAIL = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAIL.append(name)


def client(role="platform-owner", user="jriggs@auction.com"):
    c = A.app.test_client()
    with c.session_transaction() as s:
        s["user"] = user
        s["auth_at"] = int(time.time())
        s["sso"] = {"user": user, "upn": user, "name": "Jeramy Keith", "role": role,
                    "groups": ["saas-ith-sa"], "can_write": True,
                    "can_write_prod": role == "platform-owner", "auth": "entra"}
    return c


for role in ("platform-owner", "viewer"):
    print("\n--- role: %s ---" % role)
    c = client(role)
    t0 = time.time()
    r = c.get("/console")
    ms = (time.time() - t0) * 1000
    body = r.get_data(as_text=True)
    check("GET /console is 200 (%d, %.0f ms)" % (r.status_code, ms), r.status_code == 200,
          body[:400])
    if r.status_code != 200:
        continue
    views = sorted(set(re.findall(r'<section class="[^"]*\bpage\b[^"]*" data-view="([a-z]+)"', body)))
    check("all console sections rendered (%d)" % len(views), len(views) == 8, str(views))
    navs = sorted(set(re.findall(r'data-nav="([a-z]+)"', body)))
    check("nav and views are 1:1", navs == views, "nav=%s views=%s" % (navs, views))
    check("no unrendered Jinja left", "{{" not in body and "{%" not in body)
    check("CSRF token present", 'name="csrf" value=' in body)
    check("command palette data is valid JSON",
          bool(re.search(r'id="cmdk-data">(.+?)</script>', body, re.S)))
    m = re.search(r'id="cmdk-data">(.+?)</script>', body, re.S)
    if m:
        import json
        try:
            d = json.loads(m.group(1))
            check("palette has items", len(d.get("items", [])) > 0,
                  "%d items" % len(d.get("items", [])))
        except json.JSONDecodeError as e:
            check("palette JSON parses", False, str(e))
    forms = re.findall(r'<form[^>]*action="([^"]*)"', body)
    # A viewer holds no capabilities, so almost every control is correctly absent
    # - that is the permission model working, not a broken page. Only the owner
    # is expected to see the full set.
    floor = 10 if role == "platform-owner" else 1
    check("live forms present (%d, floor %d for %s)" % (len(forms), floor, role),
          len(forms) >= floor)
    check("every form posts to this origin",
          all(f.startswith("/") for f in forms), str([f for f in forms if not f.startswith("/")]))
    owner_only = "Save settings" in body
    check("settings form %s for %s" % ("shown" if role == "platform-owner" else "hidden", role),
          owner_only == (role == "platform-owner"))
    check("no prototype placeholder counts",
          "2·6" not in body and 'p-crit badge">4' not in body)

# The front door is the console now.
print("\n--- the swap ---")
c = client()
r = c.get("/")
check("GET / is 200", r.status_code == 200)
root_body = r.get_data(as_text=True)
check("GET / renders the console", 'data-nav="overview"' in root_body)
check("front door includes operations", 'data-nav="operations"' in root_body and 'data-view="operations"' in root_body)

for path, where in (("/subdomains/7", "/console#subdomains"),
                    ("/operations", "/console#overview"),
                    ("/gal", "/console#directory"),
                    ("/settings", "/console#system"),
                    ("/account", "/console#system")):
    r = c.get(path)
    check("%s -> %s" % (path, where),
          r.status_code in (301, 302) and r.headers.get("Location") == where,
          "%s %s" % (r.status_code, r.headers.get("Location")))

# _back must only ever be this console's own path.
print("\n--- return-to-console guard ---")
with client().session_transaction() as s:
    pass
c = client()
tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/console").get_data(as_text=True)).group(1)
for evil in ("https://evil.example/x", "//evil.example", "/console/../../etc", "javascript:alert(1)"):
    r = c.post("/landing/links/999/toggle", data={"csrf": tok, "_back": evil})
    loc = r.headers.get("Location", "")
    check("_back %r rejected" % evil, loc != evil, "Location=%s" % loc)
r = c.post("/landing/links/999/toggle", data={"csrf": tok, "_back": "/console#directory"})
check("_back /console#directory honoured (404 route still 404s first)",
      r.status_code == 404 or r.headers.get("Location") == "/console#directory",
      "%s %s" % (r.status_code, r.headers.get("Location")))

print("\n%s  (%d failures)" % ("ALL CHECKS PASSED" if not FAIL else "FAILURES: " + ", ".join(FAIL), len(FAIL)))
sys.exit(1 if FAIL else 0)
