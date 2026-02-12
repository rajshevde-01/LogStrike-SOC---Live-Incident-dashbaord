import win32evtlog
import pywintypes

EVENT_TYPE_LABELS = {
    win32evtlog.EVENTLOG_ERROR_TYPE: "Error",
    win32evtlog.EVENTLOG_WARNING_TYPE: "Warning",
    win32evtlog.EVENTLOG_INFORMATION_TYPE: "Information",
    win32evtlog.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
    win32evtlog.EVENTLOG_AUDIT_FAILURE: "Audit Failure",
}

def stream_security_events(limit=50):
    server = 'localhost'
    logtype = 'Security'

    try:
        hand = win32evtlog.OpenEventLog(server, logtype)
    except pywintypes.error as exc:
        logtype = 'System'
        try:
            hand = win32evtlog.OpenEventLog(server, logtype)
        except pywintypes.error as exc2:
            raise PermissionError("Event log access denied. Run as administrator.") from exc2
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = []
    total = 0

    while total < limit:
        records = win32evtlog.ReadEventLog(hand, flags, 0)
        if not records:
            break

        for ev in records:
            events.append({
                "event_id": ev.EventID & 0xffff,
                "time": str(ev.TimeGenerated),
                "source": ev.SourceName,
                "user": str(ev.Sid) if ev.Sid else "N/A",
                "host": ev.ComputerName,
                "log": logtype,
                "type": EVENT_TYPE_LABELS.get(ev.EventType, "Unknown"),
                "category": ev.EventCategory,
                "record": ev.RecordNumber,
                "inserts": [str(x) for x in (ev.StringInserts or [])]
            })
            total += 1
            if total >= limit:
                break

    return events
