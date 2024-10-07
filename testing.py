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
            
            
            
            
            

import pymupdf
import re
import csv

def crop_and_extract_text(pdf_path, output_path, text_output_path, filter_list):
    # Open the PDF document
    doc = pymupdf.open(pdf_path)

    # Date pattern to identify pages with headers to crop
    date_pattern = re.compile(r"\b(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), \d{1,2} (?:January|February|March|April|May|June|July|August|September|October|November|December), \d{4}\b")

    # Iterate through each page, skipping the first page
    for page_num in range(1, len(doc)):
        page = doc.load_page(page_num)
        
        # Extract the first part of the page text to check for the date pattern
        initial_text = page.get_text("text", clip=pymupdf.Rect(0, 0, page.rect.width, 72))
        
        # Get the original dimensions of the page
        page_rect = page.rect

        # Define the crop box dimensions based on the presence of the date pattern
        if date_pattern.search(initial_text):
            # If the date pattern is found, crop the top 1 inch and bottom 0.5 inch
            top_crop = 72  # 1 inch = 72 points
            bottom_crop = 36  # 0.5 inch = 36 points
        else:
            # Otherwise, only crop the bottom 0.5 inch
            top_crop = 0
            bottom_crop = 36

        cropped_rect = pymupdf.Rect(
            page_rect.x0,
            page_rect.y0 + top_crop,
            page_rect.x1,
            page_rect.y1 - bottom_crop
        )
        
        # Set the crop box for the page
        page.set_cropbox(cropped_rect)

    # Save the cropped version of the PDF
    doc.save(output_path)

    # Extract text from each cropped page, skipping the first page
    visible_text = []
    for page_num in range(1, len(doc)):
        page = doc.load_page(page_num)
        visible_text.append(page.get_text())

    doc.close()
    
    # Combine the extracted text for all pages
    combined_text = '\n'.join(visible_text)
    
    # Filter out lines that contain any of the strings or regex patterns in filter_list
    filtered_lines = []
    for line in combined_text.split('\n'):
        if not any(re.search(pattern, line) for pattern in filter_list):
            filtered_lines.append(line)
    
    final_text = '\n'.join(filtered_lines)
    
    # Export the final text to a .txt file
    with open(text_output_path, 'w', encoding='utf-8') as text_file:
        text_file.write(final_text)
    
    return final_text

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
            rule = {"Rule Name": line, "Conditions": [], "Actions": "", "Status": ""}
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
                        conditions.append(f"{condition_operator}\n" + '\n'.join(condition_lines))
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
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames + [f"Condition {i+1}" for i in range(max(len(rule.get("Conditions", [])) for rule in rules))])
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

# Example usage:
pdf_path = "input.pdf"
output_path = "cropped_output.pdf"
text_output_path = "extracted_text.txt"
csv_output_path = "dlp_rules.csv"
filter_list = ["pattern1", "pattern2", r"regex_pattern"]
text = crop_and_extract_text(pdf_path, output_path, text_output_path, filter_list)
parse_dlp_rules_to_csv(text, csv_output_path)

