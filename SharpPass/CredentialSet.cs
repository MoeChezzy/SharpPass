using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace SharpPass
{
    public class CredentialSet : IComparable<CredentialSet>
    {
        public static List<CredentialSet> CredentialSetList = new List<CredentialSet>();

        // TODO: Create a method to export the list of CredentialSet objects (include encryption).

        private SecureString Title;
        private SecureString Username;
        private SecureString Email;
        private SecureString Password;
        private SecureString URL;
        private SecureString[] Notes;

        private DateTime CreationDateTime;
        private DateTime LastPasswordUpdate;

        public CredentialSet(string title, string username, string email, string password, string url, string[] notes)
        {
            // Assign all fields from given parameters.
            Title = ConvertToSecureString(title);
            Username = ConvertToSecureString(username);
            Email = ConvertToSecureString(email);
            Password = ConvertToSecureString(password);
            URL = ConvertToSecureString(url);

            Notes = new SecureString[notes.Length];
            for (int i = 0; i < notes.Length; i++)
            {
                Notes[i] = ConvertToSecureString(notes[i]);
            }

            // Assign the two DateTime fields.
            CreationDateTime = DateTime.Now;
            LastPasswordUpdate = DateTime.Now;
        }

        #region Accessor Methods

        public string GetTitle()
        {
            return ConvertToString(this.Title);
        }

        public string GetUsername()
        {
            return ConvertToString(this.Username);
        }

        public string GetEmail()
        {
            return ConvertToString(this.Email);
        }

        public string GetPassword()
        {
            return ConvertToString(this.Password);
        }

        public string GetURL()
        {
            return ConvertToString(this.URL);
        }

        public string[] GetNotes()
        {
            string[] notes = new string[this.Notes.Length];
            for (int i = 0; i < Notes.Length; i++)
            {
                notes[i] = ConvertToString(Notes[i]);
            }
            return notes;
        }

        public DateTime GetCreationDateTime()
        {
            return CreationDateTime;
        }

        #endregion

        #region Mutator Methods

        // All mutator methods must be supplied with the main key.

        public bool SetTitle(string title, string mainKey)
        {
            // TODO: Implement the SetTitle mutator method as well as all of the mutator methods.
            throw new NotImplementedException();
        }

        #endregion

        public TimeSpan GetTimeSincePasswordUpdate()
        {
            return DateTime.Now.Subtract(this.LastPasswordUpdate);
        }

        public int CompareTo(CredentialSet credentialSet)
        {
            // By default, CredentialSet objects will be sorted by its Title field.
            // If multiple CredentialSet objects have the same Title (same websites), the Username field will be checked.

            int comparisonResult = string.Compare(this.GetTitle(), credentialSet.GetTitle(), StringComparison.OrdinalIgnoreCase);
            if (comparisonResult == 0)
            {
                // Both Title fields are the same.
                return string.Compare(this.GetUsername(), credentialSet.GetUsername(), StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                return comparisonResult;
            }
        }

        /// <summary>
        /// Determines whether this CredentialSet object is equal to the specified CredentialSet object.
        /// </summary>
        /// <param name="obj">The other CredentialSet object to compare equality.</param>
        /// <returns>Returns whether or not this CredentialSet object is equal to the given CredentialSet.</returns>
        public override bool Equals(object obj)
        {
            // Two CredentialSet objects are only equal if their Title and Username fields are the same.

            CredentialSet comparison = (CredentialSet)obj;
            return (this.GetTitle() == comparison.GetTitle() && this.GetUsername() == comparison.GetUsername());
        }

        /// <summary>
        /// Checks whether a CredentialSet with the same Title and Username fields already exists in the list.
        /// </summary>
        /// <param name="credentialSet">The CredentialSet object to check.</param>
        /// <returns>Returns whether or not the CredentialSet exists within the list.</returns>
        public static bool Exists(CredentialSet credentialSet)
        {
            foreach (CredentialSet listSet in CredentialSetList)
            {
                if (credentialSet.Equals(listSet))
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Converts a SecureString object to a string.
        /// </summary>
        /// <param name="input">The SecureString object to convert into a string.</param>
        /// <returns>Returns a string converted from the SecureString.</returns>
        public static string ConvertToString(SecureString input)
        {
            // Check if the SecureString object is null.
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }

            IntPtr unmanagedString = IntPtr.Zero;
            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(input);
                return Marshal.PtrToStringUni(unmanagedString);
            }
            finally
            {
                // Free the native buffer to prevent leaks.
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }

        /// <summary>
        /// Converts a string to a SecureString object.
        /// </summary>
        /// <param name="input">The string to convert into a SecureString object.</param>
        /// <returns>Returns a SecureString derived from the given string.</returns>
        public static SecureString ConvertToSecureString(string input)
        {
            // Check if the string object is null.
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }

            unsafe
            {
                fixed (char* inputCharacters = input)
                {
                    SecureString secureString = new SecureString(inputCharacters, input.Length);
                    secureString.MakeReadOnly();
                    return secureString;
                }
            }
        }
    }
}
