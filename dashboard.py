from flask import Flask, render_template, jsonify, request
from win_event_reader import stream_security_events
from detector import detect
from mitre_map import map_mitre
from collections import Counter
from datetime import datetime, timedelta

app = Flask(__name__)

ALERT_STORE = []
ALERT_SEEN = set()

RANGE_MAP = {
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24)
}

TIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z"
]


def parse_time(value):
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def filter_by_range(items, range_value):
    delta = RANGE_MAP.get(range_value)
    if not delta:
        return items

    filtered = []
    for item in items:
        dt = parse_time(item.get("time"))
        if not dt:
            continue
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
        if dt >= now - delta:
            filtered.append(item)
    return filtered

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/alerts")
def alerts():
    global ALERT_STORE
    global ALERT_SEEN
    range_value = request.args.get("range", "all")

    try:
        events = stream_security_events(100)
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403

    new_alerts = detect(events)

    deduped = []
    for a in new_alerts:
        key = f"{a.get('event_id')}|{a.get('time')}|{a.get('host')}|{a.get('rule')}"
        if key in ALERT_SEEN:
            continue
        ALERT_SEEN.add(key)
        deduped.append(a)

    ALERT_STORE.extend(deduped)
    ALERT_STORE = ALERT_STORE[-500:]
    ALERT_SEEN = {
        f"{a.get('event_id')}|{a.get('time')}|{a.get('host')}|{a.get('rule')}"
        for a in ALERT_STORE
    }

    return jsonify(filter_by_range(ALERT_STORE, range_value))


@app.route("/severity")
def severity():
    range_value = request.args.get("range", "all")
    alerts_view = filter_by_range(ALERT_STORE, range_value)
    counts = Counter(a["severity"] for a in alerts_view)

    try:
        events = stream_security_events(100)
    except PermissionError:
        return jsonify(counts)

    events_view = filter_by_range(events, range_value)
    counts["events"] += len(events_view)
    return jsonify(counts)


@app.route("/events")
def events():
    range_value = request.args.get("range", "all")
    try:
        items = stream_security_events(100)
    except PermissionError as exc:
        return jsonify({"error": str(exc)}), 403
    return jsonify(filter_by_range(items, range_value))


@app.route("/mitre_stats")
def mitre_stats():
    range_value = request.args.get("range", "all")
    alerts_view = filter_by_range(ALERT_STORE, range_value)
    counts = Counter(a["mitre"] for a in alerts_view)

    try:
        events = stream_security_events(100)
    except PermissionError:
        return jsonify(counts)

    events_view = filter_by_range(events, range_value)
    counts.update(map_mitre(e["event_id"]) for e in events_view)
    return jsonify(counts)


if __name__ == "__main__":
    print("Run as ADMIN for Security log access")
    app.run(debug=True)
