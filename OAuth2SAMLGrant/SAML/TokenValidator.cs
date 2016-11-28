using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.IdentityModel.Selectors;

namespace OAuth2SAMLGrant.SAML
{
    class TokenValidator
    {
        internal ClaimsIdentity DecryptAndValidate(string token)
        {
            string _metadataAddress = ConfigurationManager.AppSettings["METADATAADDRESS" ];
            string _identityServerSiteID = ConfigurationManager.AppSettings["IDENTITYSERVERSITEID"];
            string _resourceServerUrl2 = ConfigurationManager.AppSettings["RESOURCESERVERURL"];
            string _encryptionCertThumbprint = ConfigurationManager.AppSettings["ENCRYPTCERTTHUMBPRINT"];
            string _validationCertThumbprint = ConfigurationManager.AppSettings["SIGNCERTTHUMBPRINT"];
            

            /// Create and setup the configurations for decrypting and validating
            // the token.
            SecurityTokenHandlerConfiguration config = new SecurityTokenHandlerConfiguration();
            config.AudienceRestriction.AllowedAudienceUris.Add(new Uri(_resourceServerUrl2));
            config.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
            config.RevocationMode = X509RevocationMode.NoCheck;
            config.CertificateValidator = System.IdentityModel.Selectors.X509CertificateValidator.None;

            // Load the identity server's certificate's public key
            // to validate the token.
            X509Certificate2 validatingCert = Helpers.X509Certificates.GetFromFederationMetaData(_metadataAddress, _validationCertThumbprint, "signing");
            //new X509Certificate2(HttpContext.Current.Server.MapPath("~\\App_Data\\CertWithPublicKey.cer"));

            ConfigurationBasedIssuerNameRegistry inr = new ConfigurationBasedIssuerNameRegistry();

            // 2nd paramter value is STS name (Site ID field of "General Configuration")
            inr.AddTrustedIssuer(validatingCert.Thumbprint, _identityServerSiteID);
            config.IssuerNameRegistry = inr;
            System.Xml.XmlReader xr = XmlReader.Create(new System.IO.StringReader(token));
            // Load the resource server's certificate's public key
            // to decrypt the token.

            //On of these two lines will work for decrypting token
            //-----------------------------------------------------
            X509Certificate2 decryptingCert = Helpers.X509Certificates.GetFromFederationMetaData(_metadataAddress, _encryptionCertThumbprint, "encryption");
            //X509Certificate2 decryptingCert = X509CertificateHelper.FindByThumbprint(StoreName.My, StoreLocation.LocalMachine, X509CertificateHelper.GetFromFederationMetaData(_metadataAddress, _encryptionCertThumbprint, "encryption").Thumbprint);
            //-----------------------------------------------------

            List<SecurityToken> tokens = null;



            if (decryptingCert != null)
            {
                tokens = new List<SecurityToken>()
                {
                  new X509SecurityToken(decryptingCert)
                };

                // This part required for decrypting.
                config.ServiceTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver(tokens.AsReadOnly(), false);
            }
            // Load the configurations.
            SecurityTokenHandlerCollection handlers = System.IdentityModel.Tokens.SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection(config);
            ClaimsIdentity claimsId = null;

            if (handlers.CanReadToken(xr))
            {
                SecurityToken tmpToken = null;
                // Decrypt.
                try
                {
                    tmpToken = handlers.ReadToken(xr);
                }
                catch (Exception ex)
                {
                    throw new Exception("Error attempt to decrypt SAML token. Specific Error: " + ex.Message);
                }

                // Validate.
                System.Collections.ObjectModel.ReadOnlyCollection<ClaimsIdentity> claimsIds = null;
                try
                {
                    claimsIds = handlers.ValidateToken(tmpToken);
                }
                catch (Exception ex)
                {
                    throw new System.Security.SecurityException("Error validating SAML token. Specific Error: " + ex.Message);
                }

                claimsId = claimsIds.FirstOrDefault();
            }

            return claimsId;

        }
    }
}
