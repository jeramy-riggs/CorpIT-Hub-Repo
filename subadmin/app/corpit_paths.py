"""corpit_paths - PATH-RELEASE-20260929. Where the subdomain console's replicated
state lives, and which address this node answers on.

Every directory below is one the HA build later bind-mounts from DRBD as a whole,
so none of them may be the code directory. Every resolver fails closed: a missing
directory or a missing node address raises at import time of the caller, so the
console does not start on an empty database or on another node's address.

  SUBADMIN_STATE_DIR  default /var/lib/subdomain-admin/state   (subdomains.db,
                      config.json, permissions.json)
  GAL_STATE_DIR       default /var/lib/gal-directory            (the sync jobs' state
                      and .sync.lock; same default as /opt/gal-directory/gal-paths.js)
  CORPIT_HOST_IP      else CORPIT_HOST_IP= in /etc/corpit/node.env (node-local,
                      root-owned, never replicated)

SHARED_DIR is a constant, not an env lookup: the only writer of those files is the
root helper /usr/local/sbin/nrpi-subdomain, which sudo starts with a reset
environment, so the console must name the same fixed path the helper writes.
"""
import ipaddress
import os
import re

SUBADMIN_STATE_DEFAULT = "/var/lib/subdomain-admin/state"
SUBADMIN_CODE_DIR = "/opt/subdomain-admin"
GAL_STATE_DEFAULT = "/var/lib/gal-directory"
GAL_CODE_DIR = "/opt/gal-directory"
SHARED_DIR = "/etc/corpit/shared"
NODE_ENV_FILE = "/etc/corpit/node.env"

_NODE_ENV_LINE = re.compile(r"CORPIT_HOST_IP=([0-9.]+)[ \t]*")


class PathConfigError(RuntimeError):
    """A state directory or node setting is missing or points somewhere refused."""


def _abs(name, value):
    if not isinstance(value, str) or not os.path.isabs(value):
        raise PathConfigError("%s must be an absolute path, got %r" % (name, value))
    return os.path.normpath(value)


def _dir(name, value, default, refused):
    d = default if value in (None, "") else _abs(name, value)
    if d in refused:
        raise PathConfigError("%s points at %s; state moved in PATH-RELEASE-20260929" % (name, d))
    if not os.path.isdir(d):
        raise PathConfigError("%s: state directory %s is not available" % (name, d))
    return d


def subadmin_state_dir(env=None):
    env = os.environ if env is None else env
    return _dir("SUBADMIN_STATE_DIR", env.get("SUBADMIN_STATE_DIR"), SUBADMIN_STATE_DEFAULT,
                (SUBADMIN_CODE_DIR,))


def gal_state_dir(env=None):
    env = os.environ if env is None else env
    return _dir("GAL_STATE_DIR", env.get("GAL_STATE_DIR"), GAL_STATE_DEFAULT, (GAL_CODE_DIR,))


def gal_lock_file(env=None):
    return os.path.join(gal_state_dir(env), ".sync.lock")


def shared_file(name):
    if not name or "/" in name:
        raise PathConfigError("bad settings file name %r" % (name,))
    return os.path.join(SHARED_DIR, name)


def _valid_ip(name, raw):
    try:
        ip = ipaddress.IPv4Address(raw)
    except (ipaddress.AddressValueError, ValueError):
        raise PathConfigError("%s is not an IPv4 address: %r" % (name, raw))
    if str(ip) != raw or ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        raise PathConfigError("%s is not a usable host address: %r" % (name, raw))
    return raw


def _node_env_ip(path):
    try:
        with open(path) as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        return None
    # Same rule as load_host_ip in /usr/local/sbin/nrpi-subdomain: exactly one line that
    # starts with CORPIT_HOST_IP=, and that line must be a bare dotted quad.
    found = [l for l in lines if l.startswith("CORPIT_HOST_IP=")]
    if len(found) != 1:
        raise PathConfigError("%s must contain exactly one CORPIT_HOST_IP= line (found %d)"
                              % (path, len(found)))
    m = _NODE_ENV_LINE.fullmatch(found[0])
    if not m:
        raise PathConfigError("%s: CORPIT_HOST_IP is not a usable IPv4 address" % path)
    return _valid_ip(path, m.group(1))


def host_ip(env=None, node_env_file=NODE_ENV_FILE):
    """This node's service address. Env CORPIT_HOST_IP, else node.env. Both present
    and different is refused: the root helper only ever sees node.env."""
    env = os.environ if env is None else env
    from_env = env.get("CORPIT_HOST_IP") or None
    if from_env is not None:
        from_env = _valid_ip("CORPIT_HOST_IP", from_env)
    from_file = _node_env_ip(node_env_file)
    if from_env and from_file and from_env != from_file:
        raise PathConfigError("CORPIT_HOST_IP (%s) disagrees with %s (%s)" % (from_env, node_env_file, from_file))
    ip = from_env or from_file
    if not ip:
        raise PathConfigError("no CORPIT_HOST_IP: set it in %s" % node_env_file)
    return ip
