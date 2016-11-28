using Microsoft.Owin.Security.WsFederation;
using System;
using System.Threading.Tasks;
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using System.IdentityModel.Tokens;
//using Microsoft.IdentityModel.Claims;

namespace OWINWSFedAuthentication
{
    public class OWINStartup
    {
        //internal string saml2Token;

        private readonly string _metadataAddress = System.Configuration.ConfigurationManager.AppSettings["METADATAADDRESS"];
        private readonly string _realm = System.Configuration.ConfigurationManager.AppSettings["REALM"];
        private readonly string _homerealm = System.Configuration.ConfigurationManager.AppSettings["HOMEREALM"];

        public void ConfigureAuth(IAppBuilder app)
        {

            app.SetDefaultSignInAsAuthenticationType(WsFederationAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(
                new CookieAuthenticationOptions
                {
                    AuthenticationType = WsFederationAuthenticationDefaults.AuthenticationType
                });

            WsFederationAuthenticationOptions myFedOptions = new WsFederationAuthenticationOptions
            {

                MetadataAddress = _metadataAddress,
                Wtrealm = _realm
                   ,
                SignInAsAuthenticationType = WsFederationAuthenticationDefaults.AuthenticationType,

                TokenValidationParameters = new TokenValidationParameters
                {
                    SaveSigninToken = true
                }
            };

            myFedOptions.Notifications = new WsFederationAuthenticationNotifications();
            myFedOptions.Notifications.SecurityTokenReceived = (context) =>
            {
                string samlToken = context.ProtocolMessage.GetToken();
                //Save bootstrap token in OWIN Environment
                context.OwinContext.Set<string>("SAMLTOKEN", samlToken);

                return Task.FromResult(0);
            };
            myFedOptions.Notifications.SecurityTokenValidated = (context) =>
                {
                    //Retrieve the SAML token from the OWIN Environment and add it to the
                    //claims of the current security principle.  This token can be used later to
                    //request OAUTH2 Access Tokens for backed REST API.

                    string samlToken = context.OwinContext.Get<string>("SAMLTOKEN");
                    System.Security.Claims.Claim tClaim = new System.Security.Claims.Claim("ORIGINALTOKEN", samlToken);
                    context.AuthenticationTicket.Identity.AddClaim(tClaim);

                    return Task.FromResult(0);
                };
            myFedOptions.Notifications.RedirectToIdentityProvider = (context) =>
                {
                    if (!string.IsNullOrEmpty(_homerealm))
                    {
                        context.ProtocolMessage.Whr = _homerealm;
                    }
                    return Task.FromResult(0);
                };
            app.UseWsFederationAuthentication(myFedOptions);


        }


    }
}

