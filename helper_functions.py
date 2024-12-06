def is_valid_sender(sender: str) -> bool:
    # Define invalid characters
    invalid_chars = set(" <>")
    
    # Allowed local part characters (simplified)
    allowed_local = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-")
    # Allowed domain characters
    allowed_domain = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")

    # Check for invalid chars in the entire string
    if any(ch in invalid_chars for ch in sender):
        return False

    # Must contain exactly one '@'
    if sender.count('@') != 1:
        return False

    localpart, domainpart = sender.split('@')

    # Check local part validity
    if not localpart:  # cannot be empty
        return False
    if not all(ch in allowed_local for ch in localpart):
        return False

    # Domain checks
    if not domainpart or '.' not in domainpart:
        return False
    if not all(ch in allowed_domain for ch in domainpart):
        return False
    if domainpart[0] in ['.', '-'] or domainpart[-1] in ['.', '-']:
        return False

    labels = domainpart.split('.')
    for label in labels:
        if not label:  # Empty label (e.g., "..") not allowed
            return False
        if label[0] == '-' or label[-1] == '-':
            return False

    return True


def is_valid_recipient_email(email: str) -> bool:
    # This uses the same logic as is_valid_sender, 
    # but could be customized if recipient email rules differ.
    invalid_chars = set(" <>")
    allowed_local = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-")
    allowed_domain = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")

    # Check for invalid chars
    if any(ch in invalid_chars for ch in email):
        return False

    # Must contain exactly one '@'
    if email.count('@') != 1:
        return False

    localpart, domainpart = email.split('@')

    # Check local part
    if not localpart:
        return False
    if not all(ch in allowed_local for ch in localpart):
        return False

    # Domain checks
    if not domainpart or '.' not in domainpart:
        return False
    if not all(ch in allowed_domain for ch in domainpart):
        return False
    if domainpart[0] in ['.', '-'] or domainpart[-1] in ['.', '-']:
        return False

    labels = domainpart.split('.')
    for label in labels:
        if not label:
            return False
        if label[0] == '-' or label[-1] == '-':
            return False

    return True


def is_valid_recipient_domain(domain: str) -> bool:
    invalid_chars = set(" <>")
    allowed_domain = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")

    # Check for invalid chars
    if any(ch in invalid_chars for ch in domain):
        return False

    # Domain must contain a dot
    if '.' not in domain:
        return False

    # Check allowed chars
    if not all(ch in allowed_domain for ch in domain):
        return False

    # Cannot start or end with '.' or '-'
    if domain[0] in ['.', '-'] or domain[-1] in ['.', '-']:
        return False

    # Check each label
    labels = domain.split('.')
    for label in labels:
        if not label:
            return False
        if label[0] == '-' or label[-1] == '-':
            return False

    return True