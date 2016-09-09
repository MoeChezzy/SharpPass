# SharpPass
SharpPass is a lightweight and portable password safe.  
I'll update this, don't worry.

# Credential Sets
Every password you store is stored in a **CredentialSet** object.  
A CredentialSet object possesses the following (currently implemented) private fields as `SecureString` objects:  

`Title` represents the title of the credential set, or what service or website the password is for.
Examples would be "Google" or "LinkedIn" if the password was for your Google or LinkedIn account, respectively.  
This field cannot be blank, for obvious reasons.

`Username` represents the username of the credential set.
If the service or website only uses an e-mail address for logging in, the e-mail address should be put in this field instead.  
This field cannot be blank.

`Email` represents the e-mail address of the credential set.

`Password` is the password of the credential set.

`URL` is the URL of the website or service for the credential set.
This need not be filled in as there are some credential sets that are not online,
for example credentials to a user account for a virtual machine.

# Security
SharpPass utilizes a main key, or *master password* to secure all other credentials.
This main key is created and defined by the end user on the first run (or if a credentials file is not found).  

The main key is responsible for maintaining the security of all other credentials.
When the main key is entered to access the credentials, it will be utilized in decrypting the encrypted credential sets.

A basic check will compare the hash of the inputted main key with the saved hash of the defined main key,
disallowing access if the hashes do not match.  
In the event that an individual bypasses this check, the credentials will not be obtainable
as the inputted key wil not be the same as the key needed to correctly and successfully decrypt the credentials.  

SharpPass stores the credentials in a file called "SharpPassCredentials.txt"
(in `public static string PasswordFilename` in `Program.cs`).  
Inside this text file, two things will be stored:  
1. The hashed main key on the first line
2. All encrypted credential sets on every successive line

# Todo
Everything.
