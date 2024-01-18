import requests
import pandas as pd

# Initialize an empty list for storing data
cpeDf = []

while True:
    r2 = requests.get(f"url{footprint}{cursor}", headers=headers, verify=False)
    data2 = r2.json()
    cursor = data2.get("cursor", None)

    for j in data2["services"]:
        common_data = [j.get(field, "-") for field in ["domain", "ip_address", "port", "isp"]]
        
        cpes_list = list(dict.fromkeys(j.get("cpes", ["-"])))
        issues = j.get("issues", [{}])

        for k in cpes_list:
            for issue in issues:
                issue_data = [issue.get(field, "-") for field in ["severity", "issue_id_label", "cvss2_base_score", "title", "first_discovered_date", "timestamp", "description"]]
                cpeDf.append(common_data + [k] + issue_data)

    if cursor is None:
        break

# Convert the list to a DataFrame
df = pd.DataFrame(cpeDf, columns=cpe_headers)
