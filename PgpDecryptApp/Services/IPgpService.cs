using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace PgpDecryptApp.Services
{
    /// <summary>
    /// Pgp service
    /// </summary>
    public interface IPgpService
    {
        /// <summary>
        /// Decrypt file
        /// </summary>
        /// <param name="inputStream">Encrypted file</param>
        /// <param name="privateKeyStream">Private key</param>
        /// <param name="passPhrase">Passphrase</param>
        /// <returns></returns>
        PgpLiteralData Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase);
    }
}
