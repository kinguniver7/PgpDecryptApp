using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;
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
    public class PgpService : IPgpService
    {
        /// <summary>
        /// Decrypt file
        /// </summary>
        /// <param name="inputStream">Encrypted file</param>
        /// <param name="privateKeyStream">Private key</param>
        /// <param name="passPhrase">Passphrase</param>
        /// <returns></returns>
        public PgpLiteralData Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase)
        {
            try
            {
                PgpObject pgpObj = null;
                var pgpObjFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                var pgpScrKey = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

                if (pgpObjFactory != null)
                    pgpObj = pgpObjFactory.NextPgpObject();

                PgpEncryptedDataList pgpEncrDataList = null;
                // the first object might be a PGP marker packet.
                if (pgpObj is PgpEncryptedDataList)
                    pgpEncrDataList = (PgpEncryptedDataList)pgpObj;
                else
                    pgpEncrDataList = (PgpEncryptedDataList)pgpObjFactory.NextPgpObject();

                PgpPrivateKey pgpPrvtKey = null;
                PgpPublicKeyEncryptedData pgpPblcKeyEncrData = null;
                // decrypt
                foreach (PgpPublicKeyEncryptedData pked in pgpEncrDataList.GetEncryptedDataObjects())
                {
                    pgpPrvtKey = FindSecretKey(pgpScrKey, pked.KeyId, passPhrase.ToCharArray());

                    if (pgpPrvtKey != null)
                    {
                        pgpPblcKeyEncrData = pked;
                        break;
                    }
                }

                if (pgpPrvtKey == null)
                    throw new ArgumentException("Secret key for file not found.");


                using (Stream clear = pgpPblcKeyEncrData.GetDataStream(pgpPrvtKey))
                {
                    var plainFact = new PgpObjectFactory(clear);

                    PgpObject pgpFile = plainFact.NextPgpObject();

                    if (pgpFile is PgpCompressedData cData)
                    {
                        using (Stream compDataIn = cData.GetDataStream())
                        {
                            var of = new PgpObjectFactory(compDataIn);
                            pgpFile = of.NextPgpObject();
                            if (pgpFile is PgpOnePassSignatureList)
                            {
                                pgpFile = of.NextPgpObject();
                                return (PgpLiteralData)pgpFile;
                            }
                            else
                            {
                                return (PgpLiteralData)pgpFile;
                            }
                        }                        
                    }
                    else if (pgpFile is PgpLiteralData)
                    {
                        return (PgpLiteralData)pgpFile;
                    }
                    else if (pgpFile is PgpOnePassSignatureList)
                        throw new PgpException("Encrypted file contains a signed data - not literal data.");
                    else
                        throw new PgpException("File is not a simple encrypted file - type unknown.");
                }
               
            }
            catch (PgpException ex)
            {
                //TODO: Add log
                throw ex;
            }
        }

        #region helpers
        private PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
                return null;

            return pgpSecKey.ExtractPrivateKey(pass);
        }
        #endregion

    }
}
