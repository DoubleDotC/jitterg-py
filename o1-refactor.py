import os
import re
import pandas as pd
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def extract_dlp_policies(directory_path, output_directory, email_logs_path):
    # Read email logs
    email_logs = pd.read_csv(email_logs_path)  # Assume email logs are in CSV format
    # Convert recipients to lists and trim whitespace
    email_logs['Recipients'] = email_logs['Recipients'].apply(lambda x: [recipient.strip() for recipient in x.split(',')])

    # Explode recipients to separate rows
    email_logs_exploded = email_logs.explode('Recipients')

    # Extract domains
    email_logs['Sender_Domain'] = email_logs['Sender'].str.extract(r'@(.+)$')
    email_logs_exploded['Recipient_Domain'] = email_logs_exploded['Recipients'].str.extract(r'@(.+)$')

    # Compute counts upfront
    sender_counts = email_logs['Sender'].value_counts().to_dict()
    recipient_counts = email_logs_exploded['Recipients'].value_counts().to_dict()
    sender_domain_counts = email_logs['Sender_Domain'].value_counts().to_dict()
    recipient_domain_counts = email_logs_exploded['Recipient_Domain'].value_counts().to_dict()

    # Group counts for sender-recipient combinations
    sender_recipient_counts = email_logs_exploded.groupby(['Sender', 'Recipients']).size().to_dict()
    sender_recipient_domain_counts = email_logs_exploded.groupby(['Sender', 'Recipient_Domain']).size().to_dict()
    sender_domain_recipient_counts = email_logs_exploded.groupby(['Sender_Domain', 'Recipients']).size().to_dict()
    sender_domain_recipient_domain_counts = email_logs_exploded.groupby(['Sender_Domain', 'Recipient_Domain']).size().to_dict()

    # Iterate over each file in the directory
    for filename in os.listdir(directory_path):
        if filename.endswith(".txt"):
            try:
                with open(os.path.join(directory_path, filename), 'r', encoding='utf-8') as file:
                    content = file.read()

                    # Split policies by policy blocks (e.g., VIP, Global, Local, Local2)
                    policies = re.split(r'(?<=Actions)\s+', content)

                    vip_data = []
                    global_data = []
                    local_data = []

                    for policy in policies:
                        # Extract Policy Type
                        match = re.search(r'-EPPA-DLP-(VIP|Global|Local|Local2)', policy)
                        if not match:
                            continue

                        policy_type = match.group(1)

                        # Extract Conditions
                        conditions_match = re.search(r'Conditions\s+(.*?)\s+Actions', policy, re.DOTALL)
                        conditions_text = conditions_match.group(1).strip() if conditions_match else ""

                        # Extract specific whitelist information (emails, domains, etc.)
                        emails = re.findall(r'(?:send address contains words|Sender is):\s*(.*)', conditions_text)
                        recipient_domains = re.findall(r'Recipient domain is:\s*(.*)', conditions_text)
                        sender_domains = re.findall(r'Sender domain is:\s*(.*)', conditions_text)
                        whitelisted_recipients = re.findall(r'Recipient address contains words:\s*(.*)', conditions_text)

                        # Split the found items by comma and clean whitespace
                        emails = [email.strip() for email in ','.join(emails).split(',') if email.strip()]
                        recipient_domains = [domain.strip() for domain in ','.join(recipient_domains).split(',') if domain.strip()]
                        sender_domains = [domain.strip() for domain in ','.join(sender_domains).split(',') if domain.strip()]
                        whitelisted_recipients = [recipient.strip() for recipient in ','.join(whitelisted_recipients).split(',') if recipient.strip()]

                        # Create a unified DataFrame to hold the results
                        unified_data = {
                            "Policy Type": [],
                            "Whitelisted Item Type": [],
                            "Item": [],
                            "Number of Emails Sent": [],
                            "Number of Emails Received": []
                        }

                        # Add data for VIP Policy
                        if policy_type == "VIP":
                            for email in emails:
                                email_count = sender_counts.get(email, 0)
                                unified_data["Policy Type"].append("VIP")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Email")
                                unified_data["Item"].append(email)
                                unified_data["Number of Emails Sent"].append(email_count)
                                unified_data["Number of Emails Received"].append("")

                        # Add data for Global Policy
                        elif policy_type == "Global":
                            # For senders
                            for sender in emails:
                                email_count = sender_counts.get(sender, 0)
                                unified_data["Policy Type"].append("Global")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Sender Email")
                                unified_data["Item"].append(sender)
                                unified_data["Number of Emails Sent"].append(email_count)
                                unified_data["Number of Emails Received"].append("")
                            for domain in sender_domains:
                                email_count = sender_domain_counts.get(domain, 0)
                                unified_data["Policy Type"].append("Global")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Sender Domain")
                                unified_data["Item"].append(domain)
                                unified_data["Number of Emails Sent"].append(email_count)
                                unified_data["Number of Emails Received"].append("")
                            # For recipients
                            for domain in recipient_domains:
                                email_count = recipient_domain_counts.get(domain, 0)
                                unified_data["Policy Type"].append("Global")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Domain")
                                unified_data["Item"].append(domain)
                                unified_data["Number of Emails Sent"].append("")
                                unified_data["Number of Emails Received"].append(email_count)
                            for recipient in whitelisted_recipients:
                                email_count = recipient_counts.get(recipient, 0)
                                unified_data["Policy Type"].append("Global")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Email")
                                unified_data["Item"].append(recipient)
                                unified_data["Number of Emails Sent"].append("")
                                unified_data["Number of Emails Received"].append(email_count)

                        # Add data for Local Policy
                        elif policy_type in ["Local", "Local2"]:
                            # Combine recipient emails and domains
                            recipient_emails = whitelisted_recipients
                            recipient_domains_list = recipient_domains

                            # For senders (emails and domains)
                            for sender in emails + sender_domains:
                                if '@' in sender:
                                    # Sender is an email
                                    total_email_count = 0
                                    # Emails to recipient emails
                                    for recipient in recipient_emails:
                                        count = sender_recipient_counts.get((sender, recipient), 0)
                                        total_email_count += count
                                    # Emails to recipient domains
                                    for domain in recipient_domains_list:
                                        count = sender_recipient_domain_counts.get((sender, domain), 0)
                                        total_email_count += count
                                    unified_data["Policy Type"].append("Local")
                                    unified_data["Whitelisted Item Type"].append("Whitelisted Sender Email")
                                    unified_data["Item"].append(sender)
                                    unified_data["Number of Emails Sent"].append(total_email_count)
                                    unified_data["Number of Emails Received"].append("")
                                else:
                                    # Sender is a domain
                                    total_email_count = 0
                                    # Get all senders in the domain
                                    senders_in_domain = email_logs[email_logs['Sender_Domain'] == sender]['Sender'].unique()
                                    for s in senders_in_domain:
                                        # Emails to recipient emails
                                        for recipient in recipient_emails:
                                            count = sender_recipient_counts.get((s, recipient), 0)
                                            total_email_count += count
                                        # Emails to recipient domains
                                        for domain in recipient_domains_list:
                                            count = sender_recipient_domain_counts.get((s, domain), 0)
                                            total_email_count += count
                                    unified_data["Policy Type"].append("Local")
                                    unified_data["Whitelisted Item Type"].append("Whitelisted Sender Domain")
                                    unified_data["Item"].append(sender)
                                    unified_data["Number of Emails Sent"].append(total_email_count)
                                    unified_data["Number of Emails Received"].append("")

                            # For recipients (emails and domains)
                            for recipient in recipient_emails + recipient_domains_list:
                                if '@' in recipient:
                                    email_count = recipient_counts.get(recipient, 0)
                                    unified_data["Policy Type"].append("Local")
                                    unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Email")
                                    unified_data["Item"].append(recipient)
                                    unified_data["Number of Emails Sent"].append("")
                                    unified_data["Number of Emails Received"].append(email_count)
                                else:
                                    email_count = recipient_domain_counts.get(recipient, 0)
                                    unified_data["Policy Type"].append("Local")
                                    unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Domain")
                                    unified_data["Item"].append(recipient)
                                    unified_data["Number of Emails Sent"].append("")
                                    unified_data["Number of Emails Received"].append(email_count)

                        # Convert the unified_data dictionary to DataFrame and append
                        if policy_type == "VIP":
                            vip_data.append(pd.DataFrame(unified_data))
                        elif policy_type == "Global":
                            global_data.append(pd.DataFrame(unified_data))
                        elif policy_type in ["Local", "Local2"]:
                            local_data.append(pd.DataFrame(unified_data))

                    # Concatenate all policy DataFrames
                    vip_df = pd.concat(vip_data, ignore_index=True) if vip_data else pd.DataFrame()
                    global_df = pd.concat(global_data, ignore_index=True) if global_data else pd.DataFrame()
                    local_df = pd.concat(local_data, ignore_index=True) if local_data else pd.DataFrame()

                    # Create policy explanation text
                    policy_explanation = (
                        "VIP Policies: Whitelisted emails can send emails to any recipient.\n"
                        "Global Policies: Whitelisted senders can send emails to anyone, and anyone can send emails to whitelisted recipient domains or users.\n"
                        "Local Policies: Whitelisted senders can only send emails to whitelisted recipient domains or users.\n"
                        "\n"
                        "Number of Emails Sent: This column represents how many emails were sent by the whitelisted entity.\n"
                        "Number of Emails Received: This column represents how many emails were received by the whitelisted recipient domain or user."
                    )

                    # Create Excel writer
                    output_file_path = os.path.join(output_directory, f"{filename.split('.')[0]}_DLP_Policies.xlsx")
                    with pd.ExcelWriter(output_file_path, engine='xlsxwriter') as writer:
                        if not vip_df.empty:
                            vip_df.to_excel(writer, sheet_name="VIP Policy", index=False)
                        if not global_df.empty:
                            global_df.to_excel(writer, sheet_name="Global Policy", index=False)
                        if not local_df.empty:
                            local_df.to_excel(writer, sheet_name="Local Policy", index=False)
                        # Write policy explanation
                        workbook = writer.book
                        worksheet = workbook.add_worksheet("Policy Explanation")
                        worksheet.write(0, 0, policy_explanation)

                    logging.info(f"Excel file saved: {output_file_path}")

            except Exception as e:
                logging.error(f"Error processing file {filename}: {e}")

# Example usage
directory_path = "path/to/txt/files"  # Replace with the actual directory path containing the text files
output_directory = "path/to/output"  # Replace with the actual directory path for Excel files
email_logs_path = "path/to/email_logs.csv"  # Path to the email logs CSV file
extract_dlp_policies(directory_path, output_directory, email_logs_path)
