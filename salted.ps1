# Generate a random salt
$salt = [System.Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes(16)

# Convert the password to a byte array
$passwordBytes = [System.Text.Encoding]::UTF8.GetBytes("YourPassword")

# Combine the salt and password
$saltedPassword = [System.BitConverter]::ToString($salt + $passwordBytes)

# Hash the salted password using SHA256
$hashedPassword = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($saltedPassword))

# Convert the hashed password to a string
$hashedPasswordString = [System.BitConverter]::ToString($hashedPassword)

# Store the salt and hashed password in a secure location
# You'll need the salt to verify the password later