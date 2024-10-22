import os
import re
import pandas as pd
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def extract_dlp_policies(directory_path, output_directory, email_logs_path):
    # Read email logs
    email_logs = pd.read_csv(email_logs_path)  # Assume email logs are in CSV format
    email_logs['Recipients'] = email_logs['Recipients'].apply(lambda x: [recipient.strip() for recipient in x.split(',')])  # Convert recipients to lists and trim whitespace

    # Iterate over each file in the directory
    for filename in os.listdir(directory_path):
        if filename.endswith(".txt"):
            try:
                with open(os.path.join(directory_path, filename), 'r', encoding='utf-8') as file:
                    content = file.read()

                    # Split policies by policy blocks (e.g., VIP, Global, Local, Local2)
                    policies = re.split(r'(?<=Actions)\s+', content)

                    policy_data = []
                    related_logs = []

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
                            "Number of Emails Sent": []
                        }

                        # Function to count emails for a given set of conditions
                        def count_emails(sender_condition, recipient_condition=None):
                            filtered_logs = email_logs[email_logs['Sender'].str.contains(sender_condition, na=False)]
                            if recipient_condition:
                                filtered_logs = filtered_logs[filtered_logs['Recipients'].apply(
                                    lambda recipients: any(re.match(recipient_condition, recipient) for recipient in recipients)
                                )]
                            return filtered_logs

                        # Add data for VIP Policy
                        if policy_type == "VIP":
                            for email in emails:
                                filtered_logs = count_emails(email)
                                email_count = len(filtered_logs)
                                unified_data["Policy Type"].append("VIP")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Email")
                                unified_data["Item"].append(email)
                                unified_data["Number of Emails Sent"].append(email_count)
                                related_logs.append(filtered_logs)
                            for domain in recipient_domains:
                                unified_data["Policy Type"].append("VIP")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Domain")
                                unified_data["Item"].append(domain)
                                unified_data["Number of Emails Sent"].append("")
                            for recipient in whitelisted_recipients:
                                unified_data["Policy Type"].append("VIP")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient")
                                unified_data["Item"].append(recipient)
                                unified_data["Number of Emails Sent"].append("")

                        # Add data for Global Policy
                        elif policy_type == "Global":
                            for sender in emails + sender_domains:
                                filtered_logs = count_emails(sender, recipient_condition="|".join(recipient_domains + whitelisted_recipients))
                                email_count = len(filtered_logs)
                                unified_data["Policy Type"].append("Global")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Sender")
                                unified_data["Item"].append(sender)
                                unified_data["Number of Emails Sent"].append(email_count)
                                related_logs.append(filtered_logs)
                            for domain in recipient_domains:
                                unified_data["Policy Type"].append("Global")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Domain")
                                unified_data["Item"].append(domain)
                                unified_data["Number of Emails Sent"].append("")
                            for recipient in whitelisted_recipients:
                                unified_data["Policy Type"].append("Global")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient")
                                unified_data["Item"].append(recipient)
                                unified_data["Number of Emails Sent"].append("")

                        # Add data for Local Policy
                        elif policy_type in ["Local", "Local2"]:
                            for sender in emails + sender_domains:
                                filtered_logs = count_emails(sender, recipient_condition="|".join(recipient_domains + whitelisted_recipients))
                                email_count = len(filtered_logs)
                                unified_data["Policy Type"].append("Local")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Sender")
                                unified_data["Item"].append(sender)
                                unified_data["Number of Emails Sent"].append(email_count)
                                related_logs.append(filtered_logs)
                            for domain in recipient_domains:
                                unified_data["Policy Type"].append("Local")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Domain")
                                unified_data["Item"].append(domain)
                                unified_data["Number of Emails Sent"].append("")
                            for recipient in whitelisted_recipients:
                                unified_data["Policy Type"].append("Local")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient")
                                unified_data["Item"].append(recipient)
                                unified_data["Number of Emails Sent"].append("")

                        # Convert the unified_data dictionary to DataFrame and append
                        policy_data.append(pd.DataFrame(unified_data))

                    # Concatenate all policy DataFrames
                    final_df = pd.concat(policy_data, ignore_index=True)
                    # Concatenate all related logs DataFrames
                    if related_logs:
                        related_logs_df = pd.concat(related_logs, ignore_index=True)
                    else:
                        related_logs_df = pd.DataFrame()

                    # Create Excel writer
                    output_file_path = os.path.join(output_directory, f"{filename.split('.')[0]}_DLP_Policies.xlsx")
                    with pd.ExcelWriter(output_file_path, engine='xlsxwriter') as writer:
                        final_df.to_excel(writer, sheet_name="Policy Data", index=False)
                        if not related_logs_df.empty:
                            related_logs_df.to_excel(writer, sheet_name="Related Logs", index=False)

                    logging.info(f"Excel file saved: {output_file_path}")

            except Exception as e:
                logging.error(f"Error processing file {filename}: {e}")

# Example usage
directory_path = "path/to/txt/files"  # Replace with the actual directory path containing the text files
output_directory = "path/to/output"  # Replace with the actual directory path for Excel files
email_logs_path = "path/to/email_logs.csv"  # Path to the email logs CSV file
extract_dlp_policies(directory_path, output_directory, email_logs_path)
