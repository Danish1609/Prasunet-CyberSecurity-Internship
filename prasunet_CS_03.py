import re

def check_password_complexity(password):
    # Criteria
    min_length = 8
    has_upper = re.search(r'[A-Z]', password)
    has_lower = re.search(r'[a-z]', password)
    has_digit = re.search(r'[0-9]', password)
    has_special = re.search(r'[\W_]', password)

    # Checking the criteria
    if len(password) < min_length:
        return "\n Password must be at least 8 characters long ! "
    if not has_upper:
        return "\n Password must contain at least one uppercase letter ! "
    if not has_lower:
        return "\n Password must contain at least one lowercase letter ! "
    if not has_digit:
        return "\n Password must contain at least one digit ! "
    if not has_special:
        return "\n Password must contain at least one special character ! "

    return "\n Congrats Your Password is strong !"

def main():
    while True:
        # Get password input from the user
        password = input("\n Enter your password : ")
        result = check_password_complexity(password)
        if result == "\n Congrats Your Password is strong !":
            print(result)
            break
        else:
            print(result)
            print("\n Please Try Again !")

if __name__ == "__main__":
    main()