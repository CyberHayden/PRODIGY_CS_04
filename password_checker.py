import re

def check_password_strength(password):
    # Check length
    length_error = len(password) < 8
    
    # Check for digits
    digit_error = re.search(r"\d", password) is None
    
    # Check for uppercase characters
    uppercase_error = re.search(r"[A-Z]", password) is None
    
    # Check for lowercase characters
    lowercase_error = re.search(r"[a-z]", password) is None
    
    # Check for special characters
    special_char_error = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is None
    
    # Calculate total errors
    total_errors = length_error + digit_error + uppercase_error + lowercase_error + special_char_error
    
    if total_errors == 0:
        return "Strong Password"
    elif total_errors == 1:
        return "Moderate Password"
    else:
        return "Weak Password"

def provide_feedback(password):
    feedback = []
    
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters long.")
    if re.search(r"\d", password) is None:
        feedback.append("Password should contain at least one digit.")
    if re.search(r"[A-Z]", password) is None:
        feedback.append("Password should contain at least one uppercase letter.")
    if re.search(r"[a-z]", password) is None:
        feedback.append("Password should contain at least one lowercase letter.")
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is None:
        feedback.append("Password should contain at least one special character.")
    
    return feedback

# Example usage
if __name__ == "__main__":
    password = input("Enter your password: ")
    strength = check_password_strength(password)
    print(f"Password Strength: {strength}")
    feedback = provide_feedback(password)
    for f in feedback:
        print(f)
