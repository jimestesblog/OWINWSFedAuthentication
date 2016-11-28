using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace OAuth2SAMLGrant.Helpers
{
    class X509Certificates
    {
        internal static X509Certificate2 FindByThumbprint(StoreName storeName, StoreLocation storeLocation, string thumbprint)
        {
            var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);
            var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            X509Certificate2 cert = certificates[0];
            store.Close();
            return cert;
        }
        internal static X509Certificate2 GetFromFederationMetaData(string metadataAddress, string thumbPrint, string certUse)
        {

            System.Xml.XmlDocument metadata = new System.Xml.XmlDocument();
            metadata.Load(metadataAddress);

            XmlNodeList xnList = metadata.GetElementsByTagName("KeyDescriptor");
            string base64Cert = null;
            X509Certificate2 cert = null;
            foreach (XmlNode xN in xnList)
            {
                if (xN.Attributes["use"].Value == certUse)
                {
                    //A little hacky but it works
                    XmlNode certNode = xN.FirstChild.FirstChild.FirstChild;
                    //Todo check nod name is X509Certificate
                    base64Cert = certNode.InnerText;
                    cert = new X509Certificate2(Convert.FromBase64CharArray(base64Cert.ToCharArray(), 0, (int)base64Cert.Length));
                    if (cert.Thumbprint == thumbPrint)
                    {
                        break;
                    }

                }
            }

            return cert;
        }
    }
}
