# CorpIT live code (mirror)

What is live on corpit A + B, one folder per site (`<site>/<root>/...`). Every commit here is made by the itam launch pad
(https://dev-releases.nrpi.local/) when a release is launched or rolled back; the commit message names the release,
the signers and the CAB change, and each commit is tagged `rel-<release id>` or `rb-<release id>`.

Do not commit or push here by hand: the launch pad never force-pushes, so a commit made here stops its pushes until it is removed.
Secrets, data and dependencies are stripped (launch pad Settings > GitHub > Strip list); a file the secret scan flags is left out
and named in that commit's message.
