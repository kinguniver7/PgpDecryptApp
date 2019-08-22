using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace PgpDecryptApp.Services
{
    public class DecryptService : IDecryptService
    {
        public PgpLiteralData Decrypt(Stream inputStream, Stream privateKeyStream, string passPhrase)
        {
            try
            {
                PgpEncryptedDataList pgpEncrDataList = null;
                PgpObject pgpObj = null;
                PgpPrivateKey pgpPrvtKey = null;
                PgpPublicKeyEncryptedData pgpPblcKeyEncrData = null;

                var pgpObjFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
                var pgpScrKey = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

                if (pgpObjFactory != null)
                    pgpObj = pgpObjFactory.NextPgpObject();

                // the first object might be a PGP marker packet.
                if (pgpObj is PgpEncryptedDataList)
                    pgpEncrDataList = (PgpEncryptedDataList)pgpObj;
                else
                    pgpEncrDataList = (PgpEncryptedDataList)pgpObjFactory.NextPgpObject();

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
                    throw new ArgumentException("Secret key for message not found.");


                using (Stream clear = pgpPblcKeyEncrData.GetDataStream(pgpPrvtKey))
                {
                    PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                    PgpObject message = plainFact.NextPgpObject();

                    if (message is PgpCompressedData cData)
                    {
                        PgpObjectFactory of = null;

                        using (Stream compDataIn = cData.GetDataStream())
                        {
                            of = new PgpObjectFactory(compDataIn);
                        }

                        message = of.NextPgpObject();
                        if (message is PgpOnePassSignatureList)
                        {
                            message = of.NextPgpObject();
                            PgpLiteralData Ld = null;
                            return (PgpLiteralData)message;
                        }
                        else
                        {
                            PgpLiteralData Ld = null;
                            return (PgpLiteralData)message;
                        }
                    }
                    else if (message is PgpLiteralData)
                    {
                        return (PgpLiteralData)message;
                    }
                    else if (message is PgpOnePassSignatureList)
                        throw new PgpException("Encrypted message contains a signed message - not literal data.");
                    else
                        throw new PgpException("Message is not a simple encrypted file - type unknown.");
                }
               
            }
            catch (PgpException ex)
            {
                throw;
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
