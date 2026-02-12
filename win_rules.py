from collections import defaultdict
import time

fail_counter = defaultdict(list)

WINDOW_SEC = 120
THRESHOLD = 5

SYSTEM_USERS = ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]


def extract_ip(inserts):
    for v in inserts:
        if isinstance(v, str) and "." in v:
            return v
    return "unknown"


def detect_event(ev):

    eid = ev["event_id"]
    ins = ev["inserts"]

    # suppress system noise
    for v in ins:
        if v in SYSTEM_USERS:
            return None

    ip = extract_ip(ins)

    # brute force correlation
    if eid == 4625:
        now = time.time()
        fail_counter[ip].append(now)
        fail_counter[ip] = [t for t in fail_counter[ip] if now - t < WINDOW_SEC]

        if len(fail_counter[ip]) >= THRESHOLD:
            return {
                "title": "Brute Force Suspected",
                "type": "bruteforce",
                "ip": ip
            }

    if eid == 4672:
        return {"title": "Admin Privilege Assigned", "type": "privilege", "ip": ip}

    if eid == 4720:
        return {"title": "Account Created", "type": "account", "ip": ip}

    return None


class WindowsRuleEngine:
    def process_event(self, event_id, inserts):
        ev = {
            "event_id": event_id,
            "inserts": inserts
        }
        result = detect_event(ev)
        return [result] if result else []
