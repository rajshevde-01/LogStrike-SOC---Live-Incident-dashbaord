import time


def simulate_attack_stream(handler, iterations=20, delay=0.4):
    events = [
        {"event_id": 4625, "inserts": ["User", "10.0.0.5"]},
        {"event_id": 4625, "inserts": ["User", "10.0.0.5"]},
        {"event_id": 4625, "inserts": ["User", "10.0.0.5"]},
        {"event_id": 4625, "inserts": ["User", "10.0.0.5"]},
        {"event_id": 4625, "inserts": ["User", "10.0.0.5"]},
        {"event_id": 4672, "inserts": ["Admin", "10.0.0.5"]},
        {"event_id": 4720, "inserts": ["NewUser", "10.0.0.8"]}
    ]

    for i in range(iterations):
        ev = events[i % len(events)]
        handler(ev["event_id"], ev["inserts"])
        time.sleep(delay)
