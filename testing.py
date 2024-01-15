while True:
    # print("Cursor: %s" % (cursor))
    r2 = requests.get(
        "url"
        % (footprint, cursor),
        # first run, cursor will always be ""
        # what determines if the next cursor is None or something, it's the `footprint`
        headers=headers,
        verify=False,
    )
    data2 = r2.json()
    cursor = data2["cursor"]
    for j in data2["services"]:
        service = []
        domain = j["domain"] if "domain" in j else "-"
        ip_address = j["ip_address"] if "ip_address" in j else "-"
        port = j["port"] if "port" in j else "-"
        isp = j["isp"] if "isp" in j else "-"
        if "cpes" in j:
            cpes_list = list(dict.fromkeys(j["cpes"]))
            for k in cpes_list:
                if "issues" in j:
                    for issue in j["issues"]:
                        # change this is add row
                        # writer.writerow([ip_address,port,domain,isp,k])
                        issue_severity = (
                            issue["severity"] if "severity" in issue else "-"
                        )
                        issue_id = (
                            issue["issue_id_label"]
                            if "issue_id_label" in issue
                            else "-"
                        )
                        issue_first_discovered_date = (
                            issue["first_discovered_date"]
                            if "first_discovered_date" in issue
                            else "-"
                        )
                        issue_title = issue["title"] if "title" in issue else "-"
                        issue_timestamp = (
                            issue["timestamp"] if "timestamp" in issue else "-"
                        )
                        issue_description = (
                            issue["description"] if "description" in issue else "-"
                        )
                        issue_cvss2_base_score = (
                            issue["cvss2_base_score"]
                            if "cvss2_base_score" in issue
                            else "-"
                        )
                        cpeDf.append(
                            [
                                ip_address,
                                port,
                                domain,
                                isp,
                                k,
                                issue_severity,
                                issue_id,
                                issue_cvss2_base_score,
                                issue_title,
                                issue_first_discovered_date,
                                issue_timestamp,
                                issue_description,
                            ]
                        )
                else:
                    cpeDf.append(
                        [
                            ip_address,
                            port,
                            domain,
                            isp,
                            k,
                            "-",
                            "-",
                            "-",
                            "-",
                            "-",
                            "-",
                            "-",
                        ]
                    )
        else:
            # change this to add row
            # writer.writerow([ip_address, port, domain, isp, '-'])
            if "issues" in j:
                for issue in j["issues"]:
                    issue_severity = issue["severity"] if "severity" in issue else "-"
                    issue_id = (
                        issue["issue_id_label"] if "issue_id_label" in issue else "-"
                    )
                    issue_first_discovered_date = (
                        issue["first_discovered_date"]
                        if "first_discovered_date" in issue
                        else "-"
                    )
                    issue_title = issue["title"] if "title" in issue else "-"
                    issue_timestamp = (
                        issue["timestamp"] if "timestamp" in issue else "-"
                    )
                    issue_description = (
                        issue["description"] if "description" in issue else "-"
                    )
                    issue_cvss2_base_score = (
                        issue["cvss2_base_score"]
                        if "cvss2_base_score" in issue
                        else "-"
                    )
                    cpeDf.append(
                        [
                            ip_address,
                            port,
                            domain,
                            isp,
                            "-",
                            issue_severity,
                            issue_id,
                            issue_cvss2_base_score,
                            issue_title,
                            issue_first_discovered_date,
                            issue_timestamp,
                            issue_description,
                        ]
                    )
            else:
                cpeDf.append(
                    [
                        ip_address,
                        port,
                        domain,
                        isp,
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                    ]
                )
    if cursor is None:
        break
