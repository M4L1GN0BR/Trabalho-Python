from core.parser import load_results, get_vulnerabilities
from core.prioritization import classify_priority

print("main rodando")

data = load_results("../data/results.json")
results = get_vulnerabilities(data)

print("json carregado")
print(f"Quantidade de vulnerabilidades: {len(results)}")
print("-" * 40)

for item in results:
    check_id = item.get("check_id")
    file_path = item.get("path")
    line = item.get("start", {}).get("line")
    message = item.get("extra", {}).get("message")
    severity = item.get("extra", {}).get("severity")
    priority = classify_priority(severity)

    print(f"ID: {check_id}")
    print(f"Arquivo: {file_path}")
    print(f"Linha: {line}")
    print(f"Severidade: {severity}")
    print(f"Prioridade ASPM: {priority}")
    print(f"Descrição: {message}")
    print("-" * 40)