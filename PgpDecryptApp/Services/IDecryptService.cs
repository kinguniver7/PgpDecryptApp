using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace PgpDecryptApp.Services
{
    public interface IDecryptService
    {
        PgpLiteralData Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase);
    }
}
