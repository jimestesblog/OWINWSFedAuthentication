using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Infrastructure;
using System.Security.Claims;
using System.Configuration;
namespace OAuth2SAMLGrant
{
    class OAuthSAML2RefreshTokenProvider:AuthenticationTokenProvider
    {
        private static readonly string RefreshTokenExpireMin = ConfigurationManager.AppSettings["REFRESHTOKENEXPIREMIN"];
        
        public OAuthSAML2RefreshTokenProvider()
        {
        }

        public override void Create(AuthenticationTokenCreateContext context)
        {
            var refreshTokenId = Guid.NewGuid().ToString("n");

            var expirationTime = RefreshTokenExpireMin;
            var issuedUtc = DateTime.UtcNow;
            var expiresUtc = DateTime.UtcNow.AddMinutes(Convert.ToDouble(expirationTime));
            context.Ticket.Properties.IssuedUtc = issuedUtc;
            context.Ticket.Properties.ExpiresUtc = expiresUtc;

            AddRefreshTokenIdToClaims(context, refreshTokenId);

            string userEmail = "";
            var payload = context.SerializeTicket();

            try
            {
                var userEmailClaim = context.Ticket.Identity.FindFirst(ClaimTypes.NameIdentifier);
                if (userEmailClaim != null)
                    userEmail = userEmailClaim.Value;
            }
            catch (Exception e)
            { }

            context.SetToken(payload);
        }

        private static void AddRefreshTokenIdToClaims(AuthenticationTokenCreateContext context, string refreshTokenId)
        {
            var claim = context.Ticket.Identity.FindFirst(Claims.CustomTypes.RefreshTokenIdClaim);
            if (claim != null && claim.Value != null)
                context.Ticket.Identity.RemoveClaim(claim);

            context.Ticket.Identity.AddClaim(new Claim(Claims.CustomTypes.RefreshTokenIdClaim, refreshTokenId));
        }

        public override void Receive(AuthenticationTokenReceiveContext context)
        {
            context.DeserializeTicket(context.Token);
        }
    }
}
