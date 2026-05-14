import json

def load_results(file_path):
    with open(file_path, "r", encoding="utf-8-sig") as f:
        return json.load(f)

def get_vulnerabilities(data):
    return data.get("results", [])