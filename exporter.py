import csv
from flask import Response, jsonify

def export_json(alerts):
    return jsonify(alerts)

def export_csv(alerts):

    def gen():
        header = alerts[0].keys() if alerts else []
        yield ",".join(header) + "\n"

        for a in alerts:
            yield ",".join(str(a[k]) for k in header) + "\n"

    return Response(gen(), mimetype="text/csv")
