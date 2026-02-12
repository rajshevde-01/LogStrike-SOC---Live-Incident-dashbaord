import argparse
from win_event_reader import stream_security_events
from win_rules import WindowsRuleEngine
from simulator import simulate_attack_stream


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args()

    engine = WindowsRuleEngine()

    def handle(event_id, inserts):
        alerts = engine.process_event(event_id, inserts)
        for a in alerts:
            print("[ALERT]", a)

    if args.simulate:
        simulate_attack_stream(handle)
    else:
        events = stream_security_events(100)
        for e in events:
            handle(e["event_id"], e.get("inserts") or [])


if __name__ == "__main__":
    main()
