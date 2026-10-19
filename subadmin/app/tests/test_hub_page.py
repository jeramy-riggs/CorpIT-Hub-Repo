#!/usr/bin/env python3
"""Would 'Rebuild page now' still produce the right hub page?

Renders the template to a STRING and diffs it against the file currently being
served. Nothing is written. This is the check that matters after retiring
base.html: if corpit_page.html had inherited from it, the first rebuild would
have blanked the public hub page instead of failing loudly.
"""
import difflib
import sys

sys.path.insert(0, "/opt/subdomain-admin")
import app as A  # noqa: E402

with A.app.test_request_context("/"):
    html = A.render_template(
        "corpit_page.html",
        links=A._beta_rows(enabled_only=True),
        generated=A.now_iso(),
        base_domain=A.BASE_DOMAIN,
        host_ip=A.HOST_IP,
        host_fqdn=A.BETA_HOST_FQDN,
    )
    print("rendered OK: %d bytes, %d links"
          % (len(html), len(A._beta_rows(enabled_only=True))))

live = open(A.BETA_PAGE_PATH, encoding="utf-8").read()
diff = [l for l in difflib.unified_diff(live.splitlines(), html.splitlines(),
                                        "live", "would-render", lineterm="", n=0)]
changed = [l for l in diff if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
print("lines that would change on a rebuild: %d" % len(changed))
for l in changed[:14]:
    print("   " + l[:150])
