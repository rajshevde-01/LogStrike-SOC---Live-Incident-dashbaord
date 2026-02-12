from collections import defaultdict
from mitre_map import map_mitre

fail_counter = defaultdict(int)

def detect(events):
    alerts = []

    for e in events:
        eid = e["event_id"]

        if eid == 4625:
            fail_counter[e["host"]] += 1

            if fail_counter[e["host"]] >= 5:
                alerts.append(build_alert(e, "Brute Force Suspected", "high"))

        if eid == 4672:
            alerts.append(build_alert(e, "Admin Privilege Logon", "critical"))

        if eid == 4720:
            alerts.append(build_alert(e, "Account Created", "medium"))

        if eid == 4726:
            alerts.append(build_alert(e, "Account Deleted", "medium"))

        if eid == 4722:
            alerts.append(build_alert(e, "Account Enabled", "low"))

        if eid == 4725:
            alerts.append(build_alert(e, "Account Disabled", "low"))

        if eid == 4688:
            alerts.append(build_alert(e, "Process Created", "low"))

        if eid == 4670:
            alerts.append(build_alert(e, "Permissions Changed", "high"))

        if eid == 4719:
            alerts.append(build_alert(e, "Audit Policy Changed", "high"))

        if eid == 4697:
            alerts.append(build_alert(e, "Service Installed", "medium"))

        if eid == 1102:
            alerts.append(build_alert(e, "Security Log Cleared", "critical"))

    return alerts


def build_alert(e, rule, severity):
    return {
        "time": e["time"],
        "event_id": e["event_id"],
        "host": e["host"],
        "user": e["user"],
        "rule": rule,
        "severity": severity,
        "mitre": map_mitre(e["event_id"])
    }

