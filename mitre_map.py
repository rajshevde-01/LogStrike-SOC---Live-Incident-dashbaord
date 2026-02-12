MITRE_MAP = {
    4625: "T1110 Brute Force",
    4624: "T1078 Valid Accounts",
    4672: "T1068 Privilege Escalation",
    4720: "T1136 Create Account"
}

def map_mitre(event_id):
    return MITRE_MAP.get(event_id, "T0000 Unknown")
