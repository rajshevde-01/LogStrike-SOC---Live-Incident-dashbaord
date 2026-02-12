import random

def enrich_ip(ip):
    return {
        "country": random.choice(["US","DE","IN","SG","NL"]),
        "org": random.choice(["Cloud","ISP","DC"])
    }
