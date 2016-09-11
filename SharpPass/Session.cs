using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.IO;

namespace SharpPass
{
    public class Session
    {
        private SecureString MainKeyInput;
        private SecureString MainKeyStored;

        private SecureString[] CredentialFile;

        private bool KeysMatch;

        public Session(SecureString mainKeyInput)
        {
            MainKeyInput = mainKeyInput;

            // Check to see if the password file exists.
            if (!File.Exists(Program.GetPasswordFilepath()))
            {
                throw new FileNotFoundException("The password file was not found! It was expected to be found at " + Program.GetPasswordFilepath() + ". Restarting the program would most likely help.");
            }

            // Retrieve the text in the password file.
            string[] passwordFileText = File.ReadAllLines(Program.GetPasswordFilepath());
            CredentialFile = new SecureString[passwordFileText.Length];
            for (int i = 0; i < passwordFileText.Length; i++)
            {
                CredentialFile[i] = CredentialSet.ConvertToSecureString(passwordFileText[i]);
            }
            MainKeyStored = CredentialFile[0];

            // Compare the given hash with the stored hash.
            MainKeyInput = mainKeyInput;
            KeysMatch = SecurityHelper.Validate(CredentialSet.ConvertToString(MainKeyInput), CredentialSet.ConvertToString(MainKeyStored));
        }

        public SecureString GetMainKeyInput()
        {
            return MainKeyInput;
        }

        public SecureString GetMainKeyStored()
        {
            return MainKeyStored;
        }
    }
}
