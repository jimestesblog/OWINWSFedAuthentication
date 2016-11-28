using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace OAuth2SAMLGrant
{
    class OAuthSAML2GrantFlowProvider: OAuthAuthorizationServerProvider
    {
        private const string InvalidRefreshToken = "Invalid token";

        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var grantRefreshToken = IsRefreshTokenValid(context);

            if (!grantRefreshToken)
            {
                context.SetError(InvalidRefreshToken);
            }
            else
            {
                var identity = new ClaimsIdentity(context.Ticket.Identity);
                var ticket = new AuthenticationTicket(identity, context.Ticket.Properties);
                context.Validated(ticket);
            }

            return Task.FromResult<object>(null);
        }

        private bool IsRefreshTokenValid(OAuthGrantRefreshTokenContext context)
        {
           
            //TODO: Implement Sigle use refresh token.
            

            return true;

        }

        public override Task GrantCustomExtension(OAuthGrantCustomExtensionContext context)
        {
            context.Request.Body.Position = 0;
            string strBody = new StreamReader(context.Request.Body).ReadToEnd();
            string encAssertion = strBody.Substring(strBody.IndexOf("assertion=") + 10);

            //decode base64 string
            string assertion = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encAssertion));

            SAML.TokenValidator samlValidator = new SAML.TokenValidator();
            ClaimsIdentity cid = new ClaimsIdentity();
            try
            {

                cid = samlValidator.DecryptAndValidate(assertion);
                context.Validated(cid);
            }
            catch (System.Security.SecurityException secEx)
            { context.SetError(secEx.Message); }
            catch (Exception ex)
            { context.SetError(ex.Message); }

            return base.GrantCustomExtension(context);
        }
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated("Client");
            return base.ValidateClientAuthentication(context);
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            // TODO:logic to add custom claims to returned token
            ClaimsIdentity x = context.Identity;
            return base.TokenEndpoint(context);
        }


    }
}
