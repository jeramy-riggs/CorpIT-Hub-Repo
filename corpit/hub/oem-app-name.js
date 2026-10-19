'use strict';

// Only newly planned applications use this convention. Explicit names and
// existing Entra destinations keep their names.
function defaultEntraName(label) {
  return ('SSO-' + String(label || '').trim().replace(/^(?:SSO-)+/i, '')).slice(0, 120);
}

module.exports = { defaultEntraName };
