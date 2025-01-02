# Python Program for Secure Password Hashing & Verification

import bcrypt

#Function to hash a password
def hash_password(password):
  #Generate a salt
  salt = bcrypt.gensalt()
  #hash the password
  hashed = bcrypt.hashpw(password.encode('utf-8'),salt)
  return hashed

#Function to verify the password
def verify_password(stored_password,provided_password):
  return bcrypt.checkpw(provided_password.encode('utf-8'),stored_password)

#Example usage
if __name__ == "__main__":
  password = "supersecretpassword"
  hashed_password=hash_password(password)
  print(f"Original : {password}")
  print(f"Hashed : {hashed_password}")

#verify the passsword

password_to_check="supersecretpassword"
is_correct=verify_password(hashed_password,password_to_check)
print(f"Password verification result : {is_correct}")
