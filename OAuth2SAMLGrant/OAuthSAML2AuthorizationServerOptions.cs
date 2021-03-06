﻿using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuth2SAMLGrant
{
    public class OAuthSAML2AuthorizationServerOptions : OAuthAuthorizationServerOptions
    {
        static string _accessTokenExpire = System.Configuration.ConfigurationManager.AppSettings["ACCESSTOKENEXPIREMIN"];
        static string _allowInsecureHttp = System.Configuration.ConfigurationManager.AppSettings["ALLOWINSECUREHTTP"];
        public OAuthSAML2AuthorizationServerOptions(Func<OAuthTokenEndpointContext, System.Threading.Tasks.Task> addclaims, bool refreshTokens = false)
        {
            TokenEndpointPath = new PathString("/oauth/token");
            Provider = new OAuthSAML2GrantFlowProvider()
            {
                OnTokenEndpoint = addclaims
            };
            AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(Convert.ToInt32(_accessTokenExpire));
            AllowInsecureHttp = Convert.ToBoolean(_allowInsecureHttp);
            if (refreshTokens)
            {
               // RefreshTokenProvider = new SingleUseRefreshTokenProvider();
            }
        }

        public OAuthSAML2AuthorizationServerOptions(bool refreshTokens = false)
        {
            TokenEndpointPath = new PathString("/oauth/token");
            Provider = new OAuthSAML2GrantFlowProvider();
            AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(Convert.ToInt32(_accessTokenExpire));
            AllowInsecureHttp = Convert.ToBoolean(_allowInsecureHttp);
            if (refreshTokens)
            {
                //RefreshTokenProvider = new SingleUseRefreshTokenProvider();
            }
        }
    }
}
