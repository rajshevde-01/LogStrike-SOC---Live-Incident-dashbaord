def score_event(hit):
    return {
        "bruteforce": "critical",
        "privilege": "high",
        "account": "medium",
    }.get(hit["type"], "low")
