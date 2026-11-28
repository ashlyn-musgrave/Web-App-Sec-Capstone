import string

def password_validation_error(password):
    """
    Validates a given password and returns error messages as needed
    """
    if not isinstance(password, str):
        return "A password is required"

    if len(password) < 10:
        return "Password must contain at least 10 characters"

    if len(password) > 128:
        return "Password must not exceed 128 characters"

    if not any(char.isalpha() for char in password):
        return "Password must contain at least one letter"

    if not any(char.isupper() for char in password):
        return "Password must contain at least one uppercase letter"

    if not any(char.isdigit() for char in password):
        return "Password must contain at least one number"

    if not any(char in string.punctuation for char in password):
        return "Password must contain at least one special character"

    return None
    