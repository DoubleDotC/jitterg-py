import os
import re
import pandas as pd
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def extract_dlp_policies(directory_path, output_directory):
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
                        emails = re.findall(r'send address contains words:\s*(.*)', conditions_text)
                        recipient_domains = re.findall(r'Recipient domain is:\s*(.*)', conditions_text)
                        sender_domains = re.findall(r'Sender domain is:\s*(.*)', conditions_text)

                        # Split the found items by comma and clean whitespace
                        emails = [email.strip() for email in ','.join(emails).split(',') if email.strip()]
                        recipient_domains = [domain.strip() for domain in ','.join(recipient_domains).split(',') if domain.strip()]
                        sender_domains = [domain.strip() for domain in ','.join(sender_domains).split(',') if domain.strip()]

                        # Collect data based on policy type
                        def add_to_data(data_list, policy_type, item_type, items):
                            for item in items:
                                data_list.append({
                                    "Policy Type": policy_type,
                                    "Whitelisted Item Type": item_type,
                                    "Item": item
                                })

                        if emails:
                            add_to_data(vip_data if policy_type == "VIP" else global_data if policy_type == "Global" else local_data, policy_type, "Whitelisted Email", emails)
                        if recipient_domains:
                            add_to_data(vip_data if policy_type == "VIP" else global_data if policy_type == "Global" else local_data, policy_type, "Whitelisted Recipient Domain", recipient_domains)
                        if sender_domains:
                            add_to_data(vip_data if policy_type == "VIP" else global_data if policy_type == "Global" else local_data, policy_type, "Whitelisted Sender Domain", sender_domains)

                    # Convert collected data into pandas DataFrames
                    vip_df = pd.DataFrame(vip_data)
                    global_df = pd.DataFrame(global_data)
                    local_df = pd.DataFrame(local_data)

                    # Create Excel writer
                    output_file_path = os.path.join(output_directory, f"{filename.split('.')[0]}_DLP_Policies.xlsx")
                    with pd.ExcelWriter(output_file_path, engine='xlsxwriter') as writer:
                        if not vip_df.empty:
                            vip_df.to_excel(writer, sheet_name="VIP Policy", index=False)
                        if not global_df.empty:
                            global_df.to_excel(writer, sheet_name="Global Policy", index=False)
                        if not local_df.empty:
                            local_df.to_excel(writer, sheet_name="Local Policy", index=False)

                    logging.info(f"Excel file saved: {output_file_path}")

            except Exception as e:
                logging.error(f"Error processing file {filename}: {e}")

# Example usage
directory_path = "path/to/txt/files"  # Replace with the actual directory path containing the text files
output_directory = "path/to/output"  # Replace with the actual directory path for Excel files
extract_dlp_policies(directory_path, output_directory)