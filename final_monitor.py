import json
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import requests

SURICATA_LOG = "suricata_eve_sample.json"

def load_logs():
    events=[]
    with open(SURICATA_LOG) as f:
        for line in f:
            events.append(json.loads(line))
    return events

def analyze_suricata(events):

    findings=[]
    dns_counter=Counter()

    for e in events:

        if e["event_type"]=="alert":

            severity=e["alert"]["severity"]

            findings.append({
                "source":"suricata",
                "indicator":e["src_ip"],
                "details":e["alert"]["signature"],
                "severity":severity,
                "action":"block IP" if severity>=2 else "notify"
            })

        if e["event_type"]=="dns":

            domain=e["dns"]["rrname"]
            dns_counter[domain]+=1

    for domain,count in dns_counter.items():

        if count>=3:

            findings.append({
                "source":"suricata",
                "indicator":domain,
                "details":"frequent DNS request",
                "severity":2,
                "action":"block domain"
            })

    return findings

def vulners_demo():

    return[
        {"source":"vulners","indicator":"CVE-2024-0001","details":"Critical vulnerability","severity":9,"action":"patch system"},
        {"source":"vulners","indicator":"CVE-2024-0002","details":"High vulnerability","severity":8,"action":"update software"}
    ]

def main():

    events=load_logs()

    findings=analyze_suricata(events)

    findings+=vulners_demo()

    df=pd.DataFrame(findings)

    df.to_csv("threat_report.csv",index=False)

    print("Threats found:",len(df))

    print(df)

    df["source"].value_counts().plot(kind="bar")

    plt.title("Threat sources")

    plt.savefig("threat_chart.png")

main()
