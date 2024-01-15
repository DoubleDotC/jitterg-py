
import requests
import pandas as pd

def fetch_data(cursor, footprint, headers):
    try:
        response = requests.get(
            f"url{footprint}{cursor}", headers=headers, verify=False)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
        return None

def process_service(service):
    # Extract common fields
    ip_address = service.get("ip_address", "-")
    port = service.get("port", "-")
    domain = service.get("domain", "-")
    isp = service.get("isp", "-")

    # Process 'cpes' and 'issues' fields
    cpes_list = list(dict.fromkeys(service.get("cpes", [])))
    issues_list = service.get("issues", [{"severity": "-", "issue_id_label": "-", 
                                          "cvss2_base_score": "-", "title": "-", 
                                          "first_discovered_date": "-", "timestamp": "-", 
                                          "description": "-"}])

    return [(ip_address, port, domain, isp, cpe, issue["severity"], 
             issue["issue_id_label"], issue["cvss2_base_score"], issue["title"], 
             issue["first_discovered_date"], issue["timestamp"], issue["description"])
            for cpe in cpes_list for issue in issues_list]

def main():
    cursor = ""
    footprint = ""  # Your footprint value here
    headers = {}  # Your headers here

    all_data = []

    while True:
        data = fetch_data(cursor, footprint, headers)
        if data is None:
            break

        cursor = data.get("cursor")
        services = data.get("services", [])

        for service in services:
            all_data.extend(process_service(service))

        if cursor is None:
            break

    df = pd.DataFrame(all_data, columns=["IP Address", "Port", "Domain", "ISP", "CPE", 
                                         "Issue Severity", "Issue ID", "CVSS2 Base Score", 
                                         "Issue Title", "First Discovered Date", 
                                         "Timestamp", "Description"])
    return df

if __name__ == "__main__":
    data_frame = main()
    # You can now work with 'data_frame' or save it to a file
