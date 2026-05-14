def classify_priority(severity):
    if severity == "ERROR":
        return "Alta"
    elif severity == "WARNING":
        return "Média"
    else:
        return "Baixa"