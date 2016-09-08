﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;

namespace SharpPass
{
    static class Program
    {
        /// <summary>
        /// The name of the password file. The password file should be stored in the same directory of the executable.
        /// </summary>
        public static string PasswordFilename = "SharpPassCredentials.txt";

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Check if a password file exists.
            if (!File.Exists(string.Format("{0}\\{1}", Environment.CurrentDirectory, PasswordFilename)))
            {
                // Password file does not exist - let user create a main key.

            }
        }
    }
}
