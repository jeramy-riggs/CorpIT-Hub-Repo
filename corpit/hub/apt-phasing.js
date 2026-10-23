'use strict';

// apt prints the phased package list as indented lines after this heading.
// Stop at the next unindented line: otherwise the subsequent upgrade summary
// gets counted as phased packages and can incorrectly report zero actionable.
function phasedPackages(simulation) {
  const lines = String(simulation || '').split(/\r?\n/);
  const heading = 'The following upgrades have been deferred due to phasing:';
  const start = lines.findIndex(function (line) { return line.trim() === heading; });
  if (start === -1) return [];

  const names = [];
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line && !/^\s/.test(line)) break;
    for (const name of line.trim().split(/\s+/).filter(Boolean)) {
      if (/^[a-z0-9][a-z0-9+.:~-]*$/i.test(name)) names.push(name);
    }
  }
  return [...new Set(names)];
}

module.exports = { phasedPackages };
