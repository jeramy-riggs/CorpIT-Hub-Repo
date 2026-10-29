#!/usr/bin/env python3
"""
diagnose.py — turn raw counters into a probable cause and a next action.

Single source of truth for "what is actually wrong here". The hourly scan and
the watch poller both call this, store the result, and the UI just renders it,
so the wording never drifts between a port drawer, a trace, and a watch entry.

Each rule returns:
  key        stable id for the rule
  severity   critical | warn | info
  title      what is wrong, in plain language
  cause      the most likely physical/config reason
  action     what to actually do next
  confidence high | medium | low
  evidence   the specific numbers the call was based on

Ordering matters: the first matching rule wins, so the most specific and most
actionable causes are checked before the generic ones.
"""

def _pct(n, d):
    try: return (n / d) * 100.0
    except Exception: return 0.0

def diagnose_port(p, hist=None):
    """p: dict with port, descr, oper, admin, speed, in_err, out_err, crc,
       out_disc, mac_count, and optionally duplex ('half'/'full'/None).
       hist: optional list of {ts,oper,d_in_err,d_out_err,d_crc}."""
    name  = (p.get("port") or "")
    desc  = (p.get("descr") or "")
    oper  = p.get("oper"); admin = p.get("admin")
    speed = p.get("speed") or 0
    ie    = p.get("in_err") or 0
    oe    = p.get("out_err") or 0
    crc   = p.get("crc") or 0
    od    = p.get("out_disc") or 0
    macs  = p.get("mac_count") or 0
    low   = name.lower()
    is_fiber  = low.startswith(("te","fo","hu","twe","fi"))
    is_uplink = is_fiber or low.startswith("po") or "uplink" in desc.lower() or "downlink" in desc.lower()

    hist = hist or []
    flaps = 0
    recent_err = 0
    if hist:
        prev = None
        for h in hist:
            if prev is not None and h.get("oper") != prev: flaps += 1
            prev = h.get("oper")
            recent_err += (h.get("d_crc") or 0) + (h.get("d_in_err") or 0) + (h.get("d_out_err") or 0)

    # ── link is flapping: worse than any counter, chase this first ──
    if flaps >= 3:
        return dict(key="flapping", severity="critical", confidence="high",
            title="Link is flapping",
            cause=("This port has changed state %d times in the sampled window. That is almost always a "
                   "marginal physical connection, a failing transceiver, or a device that keeps rebooting "
                   "(check PoE if it powers the device)." % flaps),
            action="Reseat both ends of the cable, then swap the patch lead. If it persists on a fiber port, swap the SFP.",
            evidence=["%d link state changes in the window" % flaps])

    # ── CRC: the classic physical-layer fault ──
    if crc > 0 and oper == "up":
        sev = "critical" if crc >= 25 else "warn"
        if is_fiber:
            cause = ("CRC errors on a fiber/uplink port point at the optic or the fiber itself — a dirty or "
                     "failing SFP, a bend, or a mismatched optic type at one end.")
            action = "Clean or swap the SFP at both ends, then the patch fiber. Confirm both optics are the same type and wavelength."
        else:
            cause = ("Frames are arriving damaged. On copper this is a cable fault, a bad patch panel port, "
                     "interference along the run, or a duplex mismatch.")
            action = ("Replace the patch cable first (cheapest fix). If it continues, test the run and check that "
                      "both ends agree on speed/duplex.")
        ev = ["%s CRC/FCS errors" % format(crc, ",")]
        if speed and speed < 1000 and not is_fiber:
            ev.append("negotiated only %d Mbps — often a damaged pair" % speed)
        if recent_err: ev.append("%s new errors during the sampled window" % format(recent_err, ","))
        return dict(key="crc", severity=sev, confidence="high",
            title="Physical layer errors (CRC)", cause=cause, action=action, evidence=ev)

    # ── late collisions / duplex ──
    if p.get("late_coll"):
        return dict(key="duplex", severity="warn", confidence="high",
            title="Duplex mismatch",
            cause=("Late collisions mean one end is running half duplex while the other is full. It is nearly "
                   "always a hard-coded speed/duplex on one side and autonegotiation on the other."),
            action="Set both ends the same — auto/auto is usually correct — then clear counters and recheck.",
            evidence=["%s late collisions" % format(p.get("late_coll"), ",")])
    # ── input errors without CRC ──
    if ie >= 50 and crc == 0:
        return dict(key="inerr", severity="warn", confidence="medium",
            title="Inbound frames being dropped",
            cause=("Errors on receive with no CRC usually means runts/giants or an MTU disagreement, or a NIC "
                   "driver problem on the connected device."),
            action="Check the endpoint's NIC driver and MTU. If it is a trunk, confirm both ends agree on MTU and tagging.",
            evidence=["%s input errors" % format(ie, ",")])
    if oe >= 50:
        return dict(key="outerr", severity="warn", confidence="medium",
            title="Outbound transmit errors",
            cause="The switch is failing to transmit cleanly — typically a cable fault or a saturated, mismatched link.",
            action="Replace the patch cable and confirm the negotiated speed/duplex on both ends.",
            evidence=["%s output errors" % format(oe, ",")])

    # ── congestion ──
    if od >= 250000:
        sev = "warn" if od < 2_000_000 else "critical"
        cause = ("The switch is discarding frames it could not queue. On an uplink this means the link is "
                 "oversubscribed; on an access port it usually means a slow device behind a fast port, or a "
                 "burst the buffer could not absorb.")
        action = ("If this is an uplink, look at bundling more capacity or moving heavy talkers. If it is an "
                  "access port, check the endpoint's speed and whether it is doing large backups/imaging.")
        return dict(key="discards", severity=sev, confidence="medium" if is_uplink else "low",
            title="Congestion — frames discarded", cause=cause, action=action,
            evidence=["%s output discards" % format(od, ","),
                      ("uplink/trunk port" if is_uplink else "access port")])

    # ── half duplex on a live link ──
    # Deliberately below the counter rules: a half-duplex port that is also
    # dropping frames has a louder, higher-severity story to tell, and
    # net_port_issues only keeps one diagnosis per port. Also requires a link —
    # dot3StatsDuplexStatus is meaningless on a port that never negotiated.
    if oper == "up" and p.get("duplex") == "half" and speed >= 100:
        return dict(key="halfduplex", severity="warn", confidence="medium",
            title="Running half duplex",
            cause="A modern link should negotiate full duplex. Half duplex means a negotiation failure or a forced setting.",
            action="Check the port config and the device NIC; set both to autonegotiate.",
            evidence=["half duplex at %d Mbps" % speed])

    # ── administratively up but dark ──
    if admin == "up" and oper in ("down", "lowerLayerDown"):
        if macs == 0 and (ie or oe or crc or od):
            return dict(key="unplugged", severity="info", confidence="medium",
                title="Port is enabled but nothing is connected",
                cause=("The port is still configured and has carried traffic before, so the device was most "
                       "likely unplugged, moved, or powered off."),
                action="Confirm the device was meant to move. If the port is now spare, describe it as spare so it stops being flagged.",
                evidence=["link %s while admin up" % oper, ("described as '%s'" % desc) if desc else "no description"])
        return dict(key="down", severity="info", confidence="low",
            title="Port is down",
            cause="No link detected. Either nothing is plugged in, or the far end is off.",
            action="No action needed unless this port is supposed to be live.",
            evidence=["link %s" % oper])

    # ── speed sanity on a healthy port ──
    if oper == "up" and speed and speed <= 100 and not is_fiber and macs > 0:
        return dict(key="slowlink", severity="info", confidence="medium",
            title="Link negotiated below gigabit",
            cause=("A gigabit-capable port running at %d Mbps usually means a damaged pair in the cable, a "
                   "cheap/old patch lead, or a device that only supports fast ethernet." % speed),
            action="Swap the patch cable to a known-good Cat5e/Cat6. If it stays, the endpoint is the limit.",
            evidence=["negotiated %d Mbps" % speed])

    if oper == "up":
        return dict(key="healthy", severity="ok", confidence="high",
            title="No faults detected",
            cause="Link is up with clean counters.", action="",
            evidence=(["%d Mbps" % speed] if speed else []) + (["%d device(s) learned" % macs] if macs else []))
    return None


def diagnose_wifi(rssi=None, snr=None, events=None, status=None):
    """Wireless client / AP health from Meraki signal + connection events."""
    events = events or []
    poor = [e for e in events if any(w in str(e.get("reason") or "").lower()
                                     for w in ("poor", "low ack", "fail", "timeout", "deauth"))]
    disc = [e for e in events if str(e.get("type") or "") == "disconnect"]
    aps  = set(e.get("ap") for e in events if e.get("ap"))

    if status and str(status).lower() not in ("online", "up"):
        return dict(key="ap_offline", severity="critical", confidence="high",
            title="Access point is offline",
            cause="The AP is not checking in to Meraki — it has lost power, PoE, or its uplink.",
            action="Check the switch port that feeds this AP: is the link up and is PoE delivering?",
            evidence=["status %s" % status])

    if rssi is not None and rssi < -75:
        return dict(key="rssi_bad", severity="critical", confidence="high",
            title="Very weak Wi-Fi signal",
            cause=("At %d dBm the client is far outside comfortable range. Expect slow throughput, retries and "
                   "drops. Usually distance, a wall/floor in the way, or the client clinging to a distant AP." % rssi),
            action="Move the client or the AP, or add coverage. If an AP is closer, the client is 'sticky' — bounce its Wi-Fi.",
            evidence=["RSSI %d dBm" % rssi] + (["SNR %d dB" % snr] if snr is not None else []))
    if rssi is not None and rssi < -70:
        return dict(key="rssi_weak", severity="warn", confidence="medium",
            title="Weak Wi-Fi signal",
            cause="%d dBm is workable but marginal; it degrades quickly when the client moves or the band gets busy." % rssi,
            action="Check coverage in that area; consider moving the client closer or adding an AP.",
            evidence=["RSSI %d dBm" % rssi] + (["SNR %d dB" % snr] if snr is not None else []))
    if snr is not None and snr < 20:
        return dict(key="snr", severity="warn", confidence="medium",
            title="Noisy RF environment",
            cause=("Signal-to-noise of %d dB means interference is competing with the AP — other networks, "
                   "microwaves, Bluetooth, or dense client load on the channel." % snr),
            action="Look at channel utilisation and consider a channel change or moving the client to 5 GHz.",
            evidence=["SNR %d dB" % snr])
    if len(poor) >= 3:
        return dict(key="wifi_drops", severity="warn", confidence="high",
            title="Repeated poor-signal disconnects",
            cause=("This client keeps dropping with signal-quality reasons%s. That pattern is coverage or "
                   "roaming, not the client's software." % (" across %d APs" % len(aps) if len(aps) > 1 else "")),
            action="Check coverage along the client's path; if it spans several APs, review roaming/min-bitrate settings.",
            evidence=["%d poor-signal events" % len(poor), "%d disconnects total" % len(disc)])
    if len(disc) >= 8:
        return dict(key="wifi_unstable", severity="warn", confidence="medium",
            title="Frequently disconnecting",
            cause="A high disconnect count with no single signal reason — often power saving, a driver, or DHCP/auth timeouts.",
            action="Check the client's Wi-Fi driver and power management, and confirm DHCP scope health for that VLAN.",
            evidence=["%d disconnects in the window" % len(disc)])
    if rssi is not None:
        return dict(key="wifi_ok", severity="ok", confidence="high",
            title="Wireless looks healthy",
            cause="Signal and connection history are within normal range.", action="",
            evidence=["RSSI %d dBm" % rssi] + (["SNR %d dB" % snr] if snr is not None else []))
    return None


def diagnose_reach(device=None, gateway=None):
    """Liveness for the device and its gateway.

    ICMP is unreliable on endpoints - macOS and Windows block it by default - so a
    silent ping only means something when ARP, CAM and TCP are silent too."""
    if device and device.get("present") and not device.get("icmp"):
        ev = [x for x in [device.get("evidence"),
              ("TCP :%s %s" % (device.get("tcp_port"), device.get("tcp_how"))) if device.get("tcp") else None] if x]
        return dict(key="icmp_blocked", severity="ok", confidence="high",
            title="Device is present (does not answer ping)",
            cause=("No ICMP reply, but the network can still see it - %s. Most Macs and Windows "
                   "machines drop ping by default, so this on its own is not a fault."
                   % (device.get("evidence") or "seen recently")),
            action="", evidence=ev)
    if device and not device.get("alive") and device.get("present") is not True:
        if gateway and not gateway.get("alive"):
            return dict(key="segment_down", severity="critical", confidence="high",
                title="Device and gateway both unreachable",
                cause="Nothing on that subnet is answering, so this is a VLAN, uplink, or routing problem — not the device.",
                action="Check the uplink and SVI for that VLAN before touching the endpoint.",
                evidence=["device no reply", "gateway %s no reply" % (gateway.get("ip") or "")])
        # Name only the checks that ran: the watch poller pings but has no TCP probe,
        # and present=None means ARP/CAM were not looked at.
        ran = ["no ping reply"]
        if "tcp" in device: ran.append("no TCP answer")
        if device.get("present") is False: ran.append("not in ARP or the switch tables recently")
        return dict(key="device_down", severity="critical", confidence="medium",
            title="Device is not responding",
            cause=("Nothing answers for this device - %s. Most likely powered off or disconnected."
                   % ", ".join(ran)),
            action="Check the switch port for link; if the port is up, the endpoint itself is down.",
            evidence=ran)
    if device and device.get("loss_pct", 0) > 0:
        return dict(key="loss", severity="warn", confidence="medium",
            title="Intermittent packet loss",
            cause="Some pings are being dropped — marginal cabling, congestion, or a saturated wireless link.",
            action="Check the port's error counters and, if wireless, the client's signal.",
            evidence=["%d%% packet loss" % device.get("loss_pct", 0)])
    if device and device.get("rtt_ms") is not None and device["rtt_ms"] > 150:
        return dict(key="latency", severity="warn", confidence="low",
            title="High latency",
            cause="Round-trip time is well above a LAN baseline — congestion, a slow link, or a distant path.",
            action="Check utilisation on the path and whether the device is on Wi-Fi at low signal.",
            evidence=["%s ms round trip" % device["rtt_ms"]])
    return None


def worst(*ds):
    """Pick the most serious diagnosis from several."""
    order = {"critical": 0, "warn": 1, "info": 2, "ok": 3}
    got = [d for d in ds if d]
    if not got: return None
    return sorted(got, key=lambda d: order.get(d.get("severity"), 4))[0]
