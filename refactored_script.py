import os
import re
import pandas as pd
import logging
import ast

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def extract_dlp_policies(directory_path, output_directory, email_logs_path):
    # Read email logs
    email_logs = pd.read_csv(email_logs_path)  # Assume email logs are in CSV format
    
    # Clean and normalize the recipients data
    def normalize_recipients(recipients_str):
        try:
            # Remove outer quotes if present
            recipients_str = recipients_str.strip("'\"")
            # Safely convert the string representation of a list to an actual list
            recipients_list = ast.literal_eval(recipients_str)
            # Convert all recipients to lowercase
            return [recipient.lower() for recipient in recipients_list]
        except (ValueError, SyntaxError):
            # If it can't be converted, return an empty list or handle appropriately
            return []

    # Apply normalization to the Recipients column and convert Sender to lowercase
    email_logs['Recipients'] = email_logs['Recipients'].apply(normalize_recipients)
    email_logs['Sender'] = email_logs['Sender'].str.lower()

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
                    related_logs = []

                    # Initialize log processing for VIP, Global, and Local policies
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

                        # Split the found items by comma and clean whitespace, then convert to lowercase
                        emails = [email.strip().lower() for email in ','.join(emails).split(',') if email.strip()]
                        recipient_domains = [domain.strip().lower() for domain in ','.join(recipient_domains).split(',') if domain.strip()]
                        sender_domains = [domain.strip().lower() for domain in ','.join(sender_domains).split(',') if domain.strip()]
                        whitelisted_recipients = [recipient.strip().lower() for recipient in ','.join(whitelisted_recipients).split(',') if recipient.strip()]

                        # Combine senders and recipients for filtering
                        all_senders = emails + sender_domains
                        all_recipients = recipient_domains + whitelisted_recipients

                        # Create a unified dictionary to hold the results
                        unified_data = {
                            "Policy Type": [],
                            "Whitelisted Item Type": [],
                            "Item": [],
                            "Number of Emails Sent": [],
                            "Number of Emails Received": []
                        }

                        # Function to filter email logs based on senders or recipients
                        def filter_logs_by_sender(senders):
                            sender_pattern = '|'.join([re.escape(sender) for sender in senders])
                            return email_logs[email_logs['Sender'].str.contains(sender_pattern, na=False)]

                        def filter_logs_by_recipient(recipients, domains):
                            def recipient_match(recipient_list):
                                for recipient in recipient_list:
                                    if recipient in recipients:
                                        return True
                                    domain = recipient.split('@')[-1]
                                    if domain in domains:
                                        return True
                                return False
                            return email_logs[email_logs['Recipients'].apply(recipient_match)]

                        # Process VIP Policy: Count emails sent by whitelisted senders
                        if policy_type == "VIP":
                            vip_logs = filter_logs_by_sender(all_senders)
                            related_logs.append(vip_logs)
                            for sender in all_senders:
                                count = vip_logs[vip_logs['Sender'] == sender].shape[0]
                                unified_data["Policy Type"].append("VIP")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Sender")
                                unified_data["Item"].append(sender)
                                unified_data["Number of Emails Sent"].append(count)
                                unified_data["Number of Emails Received"].append("")
                            for domain in recipient_domains:
                                unified_data["Policy Type"].append("VIP")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Domain")
                                unified_data["Item"].append(domain)
                                unified_data["Number of Emails Sent"].append("")
                                unified_data["Number of Emails Received"].append("")

                        # Process Global Policy: Count emails sent by whitelisted senders and received by whitelisted domains/users
                        elif policy_type == "Global":
                            global_logs_sender = filter_logs_by_sender(all_senders)
                            global_logs_recipient = filter_logs_by_recipient(whitelisted_recipients, recipient_domains)
                            related_logs.append(global_logs_sender)
                            related_logs.append(global_logs_recipient)
                            for sender in all_senders:
                                count = global_logs_sender[global_logs_sender['Sender'] == sender].shape[0]
                                unified_data["Policy Type"].append("Global")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Sender")
                                unified_data["Item"].append(sender)
                                unified_data["Number of Emails Sent"].append(count)
                                unified_data["Number of Emails Received"].append("")
                            for recipient in whitelisted_recipients:
                                count = global_logs_recipient[global_logs_recipient['Recipients'].apply(lambda x: recipient in x)].shape[0]
                                unified_data["Policy Type"].append("Global")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Email")
                                unified_data["Item"].append(recipient)
                                unified_data["Number of Emails Sent"].append("")
                                unified_data["Number of Emails Received"].append(count)
                            for domain in recipient_domains:
                                count = global_logs_recipient[global_logs_recipient['Recipients'].apply(
                                    lambda x: any(recipient.split('@')[-1] == domain for recipient in x)
                                )].shape[0]
                                unified_data["Policy Type"].append("Global")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Domain")
                                unified_data["Item"].append(domain)
                                unified_data["Number of Emails Sent"].append("")
                                unified_data["Number of Emails Received"].append(count)

                        # Process Local Policy: Count emails only between whitelisted senders and recipients
                        elif policy_type in ["Local", "Local2"]:
                            local_logs = filter_logs_by_sender(all_senders)
                            local_logs = local_logs[local_logs['Recipients'].apply(
                                lambda recipient_list: any(
                                    recipient in whitelisted_recipients or recipient.split('@')[-1] in recipient_domains
                                    for recipient in recipient_list
                                )
                            )]
                            related_logs.append(local_logs)
                            for sender in all_senders:
                                count = local_logs[local_logs['Sender'] == sender].shape[0]
                                unified_data["Policy Type"].append("Local")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Sender")
                                unified_data["Item"].append(sender)
                                unified_data["Number of Emails Sent"].append(count)
                                unified_data["Number of Emails Received"].append("")
                            for recipient in whitelisted_recipients:
                                count = local_logs[local_logs['Recipients'].apply(lambda x: recipient in x)].shape[0]
                                unified_data["Policy Type"].append("Local")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Email")
                                unified_data["Item"].append(recipient)
                                unified_data["Number of Emails Sent"].append("")
                                unified_data["Number of Emails Received"].append(count)
                            for domain in recipient_domains:
                                count = local_logs[local_logs['Recipients'].apply(
                                    lambda x: any(recipient.split('@')[-1] == domain for recipient in x)
                                )].shape[0]
                                unified_data["Policy Type"].append("Local")
                                unified_data["Whitelisted Item Type"].append("Whitelisted Recipient Domain")
                                unified_data["Item"].append(domain)
                                unified_data["Number of Emails Sent"].append("")
                                unified_data["Number of Emails Received"].append(count)

                        # Collect the unified data into the appropriate policy list
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
                    related_logs_df = pd.concat(related_logs, ignore_index=True) if related_logs else pd.DataFrame()

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
                        if not related_logs_df.empty:
                            related_logs_df.to_excel(writer, sheet_name="Related Logs", index=False)
                        
                        # Add the Policy Explanation Sheet with formatted text
                        workbook = writer.book
                        worksheet = workbook.add_worksheet("Policy Explanation")
                        wrap_format = workbook.add_format({'text_wrap': True, 'valign': 'top'})
                        
                        worksheet.write(0, 0, policy_explanation, wrap_format)
                        worksheet.set_column(0, 0, 100)  # Set column width for better readability

                    logging.info(f"Excel file saved: {output_file_path}")

            except Exception as e:
                logging.error(f"Error processing file {filename}: {e}")

# Example usage
directory_path = "path/to/txt/files"  # Replace with the actual directory path containing the text files
output_directory = "path/to/output"  # Replace with the actual directory path for Excel files
email_logs_path = "path/to/email_logs.csv"  # Path to the email logs CSV file
extract_dlp_policies(directory_path, output_directory, email_logs_path)