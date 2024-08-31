import re

def password_strength(password):
    # Initialize strength points
    strength_points = 0
    
    # Length of the password
    if len(password) >= 8:
        strength_points += 1
    
    # Check for uppercase letters
    if re.search(r'[A-Z]', password):
        strength_points += 1
    
    # Check for lowercase letters
    if re.search(r'[a-z]', password):
        strength_points += 1
    
    # Check for digits
    if re.search(r'[0-9]', password):
        strength_points += 1
    
    # Check for special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength_points += 1
    
    # Provide feedback based on the strength
    if strength_points == 5:
        return "Strong"
    elif strength_points == 4:
        return "Moderate"
    else:
        return "Weak"

# Main loop
while True:
    password = input("Enter a password to check its strength (or type 'exit' to quit): ")
    if password.lower() == 'exit':
        print("Exiting the password checker.")
        break
    print(f"Password strength: {password_strength(password)}\n")
