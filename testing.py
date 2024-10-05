def parse_dlp_rules_to_csv(text, csv_output_path):
    rules = []
    lines = text.split('\n')
    rule = {}
    conditions = []
    i = 0

    while i < len(lines):
        line = lines[i].strip()
        if "-DLP-" in line:
            if rule:
                rule["Conditions"] = conditions
                rules.append(rule)
            rule = {"Rule Name": line, "Conditions": [],
                    "Actions": "", "Status": ""}
            conditions = []
        elif "Conditions" in line:
            i += 1
            condition_lines = []
            while i < len(lines) and "Actions" not in lines[i] and lines[i].strip() not in ["And", "Or"]:
                condition_lines.append(lines[i].strip())
                i += 1
            if condition_lines:
                conditions.append('\n'.join(condition_lines))
            while i < len(lines) and "Actions" not in lines[i]:
                if lines[i].strip() in ["And", "Or"]:
                    condition_operator = lines[i].strip()
                    i += 1
                    condition_lines = []
                    while i < len(lines) and "Actions" not in lines[i] and lines[i].strip() not in ["And", "Or"]:
                        condition_lines.append(lines[i].strip())
                        i += 1
                    if condition_lines:
                        conditions.append(
                            f"{condition_operator}\n" + '\n'.join(condition_lines))
                else:
                    i += 1
            continue
        elif "Actions" in line:
            actions = []
            i += 1
            while i < len(lines) and lines[i].strip() not in ["On", "Off"]:
                actions.append(lines[i].strip())
                i += 1
            rule["Actions"] = '\n'.join(actions)
            continue
        elif line in ["On", "Off"]:
            rule["Status"] = line
            rule["Conditions"] = conditions
            rules.append(rule)
            rule = {}
            conditions = []
        i += 1

    if rule:
        rule["Conditions"] = conditions
        rules.append(rule)

    with open(csv_output_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ["Rule Name", "Actions", "Status"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames + [f"Condition {i+1}" for i in range(
            max(len(rule.get("Conditions", [])) for rule in rules))])
        writer.writeheader()
        for rule in rules:
            row = {
                "Rule Name": rule.get("Rule Name", ""),
                "Actions": rule.get("Actions", ""),
                "Status": rule.get("Status", "")
            }
            for idx, condition in enumerate(rule.get("Conditions", [])):
                row[f"Condition {idx + 1}"] = condition
            writer.writerow(row)
