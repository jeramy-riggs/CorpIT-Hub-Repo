#!/usr/bin/env python3
# patch-sdp-server.py
# Adds SDP router require + mount to server.js, just before app.listen()
# Safe to run: checks for existing patch, creates backup, validates result

import re
import sys
import shutil
from datetime import datetime

SERVER_PATH = '/var/www/api-beta/server.js'
BACKUP_PATH = f'/var/www/api-beta/server.js.bak-sdp-{datetime.now().strftime("%Y%m%d%H%M%S")}'

# The two lines we want to insert
PATCH_LINES = '''
const sdpRouter = require("./sdp-routes");
app.use("/api/sdp", sdpRouter);
'''

# The line we insert BEFORE
TARGET_LINE = 'app.listen(PORT, () => {'

# --- Read file ---
with open(SERVER_PATH, 'r') as f:
    content = f.read()

# --- Check if already patched ---
if 'sdpRouter' in content:
    print('✅ Already patched — sdpRouter already present in server.js. No changes made.')
    sys.exit(0)

# --- Check target line exists ---
if TARGET_LINE not in content:
    print(f'❌ Could not find target line: "{TARGET_LINE}"')
    print('   server.js may have changed. Aborting — no changes made.')
    sys.exit(1)

# --- Backup ---
shutil.copy2(SERVER_PATH, BACKUP_PATH)
print(f'📦 Backup created: {BACKUP_PATH}')

# --- Apply patch ---
new_content = content.replace(TARGET_LINE, PATCH_LINES.lstrip('\n') + TARGET_LINE)

# --- Write ---
with open(SERVER_PATH, 'w') as f:
    f.write(new_content)

# --- Verify ---
with open(SERVER_PATH, 'r') as f:
    verify = f.read()

if 'sdpRouter' in verify and TARGET_LINE in verify:
    print('✅ Patch applied successfully.')
    print('   Added: const sdpRouter = require("./sdp-routes");')
    print('   Added: app.use("/api/sdp", sdpRouter);')
else:
    print('❌ Verification failed — restoring backup.')
    shutil.copy2(BACKUP_PATH, SERVER_PATH)
    sys.exit(1)
