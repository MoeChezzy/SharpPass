using System;
using System.Text;
using System.Security.Cryptography;

namespace SharpPass
{
    public class HashHelper
    {
        private const int SaltByteSize = 64; // Default: 24
        private const int HashByteSize = 256; // Default: 20
        private const int PBKDF2Iterations = 2000;
        private const int IterationIndex = 0;
        private const int SaltIndex = 1;
        private const int PBKDF2Index = 2;

        /// <summary>
        /// Hashes a string using the PBKDF2 algorithm.
        /// </summary>
        /// <param name="input">The string to be hashed.</param>
        /// <returns>Returns a hashed string.</returns>
        public static string Hash(string input)
        {
            RNGCryptoServiceProvider cryptoProvider = new RNGCryptoServiceProvider();
            byte[] salt = new byte[SaltByteSize];
            cryptoProvider.GetBytes(salt);

            byte[] hash = GetPBKDF2Bytes(input, salt, PBKDF2Iterations, HashByteSize);
            return string.Format("{0}:{1}:{2}", Convert.ToBase64String(Encoding.UTF8.GetBytes(PBKDF2Iterations.ToString())), Convert.ToBase64String(salt), Convert.ToBase64String(hash));
        }

        /// <summary>
        /// Checks whether a given string matches a hash.
        /// </summary>
        /// <param name="input">The plaintext string to check.</param>
        /// <param name="validationHash">The hash to validate against.</param>
        /// <returns>Returns whether the string is valid.</returns>
        public static bool Validate(string input, string validationHash)
        {
            char[] delimiter = { ':' };
            string[] split = validationHash.Split(delimiter);
            int iterations = int.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(split[IterationIndex])));
            byte[] salt = Convert.FromBase64String(split[SaltIndex]);
            byte[] hash = Convert.FromBase64String(split[PBKDF2Index]);

            byte[] testHash = GetPBKDF2Bytes(input, salt, iterations, hash.Length);
            return Check(hash, testHash);
        }

        private static bool Check(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }

        private static byte[] GetPBKDF2Bytes(string password, byte[] salt, int iterations, int outputBytes)
        {
            Rfc2898DeriveBytes PBKDF2 = new Rfc2898DeriveBytes(password, salt);
            PBKDF2.IterationCount = iterations;
            return PBKDF2.GetBytes(outputBytes);
        }
    }
}
