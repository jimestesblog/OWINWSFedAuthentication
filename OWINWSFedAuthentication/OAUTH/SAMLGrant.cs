using Newtonsoft.Json;
using OAuth2SAMLGrant.Model;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace OAuth2SAMLGrant.OAUTH
{
    public class SAMLGrant
    {

        private const string Payload = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-bearer&assertion=";
        private const string Endpoint = "oauth/token";
        private const string ContentType = "application/x-www-form-urlencoded";
        private string ResourceServerUri = ConfigurationManager.AppSettings["API"];


        public async Task<OAuthToken> RequestServiceToken()
        {

            var payload = GetPostData();
            var request = GetRequest(ResourceServerUri, payload);
            Task<string> tokenResponse = SendRequest(request);
            string serviceResponse = await tokenResponse;
            OAuthToken OAuthToken = ParseResponse(serviceResponse);

            return OAuthToken;
        }

        private byte[] GetPostData()
        {

            System.Security.Claims.ClaimsIdentity ci = System.Web.HttpContext.Current.GetOwinContext().Authentication.User.Identity as System.Security.Claims.ClaimsIdentity;





            //JRE 7-11-2015: Retrieve BOOTSTRAP Token from "ORIGINALTOKEN" Claim
            string samlToken = null;
            foreach (System.Security.Claims.Claim clm in ci.Claims)
            {

                if (clm.Type == "ORIGINALTOKEN")
                {
                    samlToken = clm.Value;
                }

            }


            //JRE 7-11-2015: Changed code to store BOOTSTRAP token in a claim on the user principle
            //string saml2Token = Convert.ToBase64String(Encoding.UTF8.GetBytes(WSFed_Owin_MVC_Startup.saml2Token));
            string saml2Token = Convert.ToBase64String(Encoding.UTF8.GetBytes(samlToken));
            string postData = Payload +
                              saml2Token;
            return Encoding.UTF8.GetBytes(postData);
        }

        private HttpRequestMessage GetRequest(string serviceUrl, byte[] payload)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, serviceUrl + Endpoint);
            request.Content = new ByteArrayContent(payload);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(ContentType);

            return request;
        }

        private async Task<string> SendRequest(HttpRequestMessage request)
        {
            using (var client = new HttpClient())
            {
                var response = await client.SendAsync(request);
                string rContent = null;

                rContent = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    string responsePayload = await response.Content.ReadAsStringAsync();
                    return responsePayload;
                }
                else
                {

                    return "Exception:" + rContent;

                }


            }
        }


        private OAuthToken ParseResponse(string serviceResponse)
        {
            if (serviceResponse.StartsWith("Exception:"))
            {
                OAuthToken errorToken = new OAuthToken();
                errorToken.setError(serviceResponse);
                return errorToken;
            }
            else
            {
                var response = JsonConvert.DeserializeObject<OAuthToken>(serviceResponse);

                response.OAuthEndpointUri = ResourceServerUri + Endpoint;
                response.ResourceServerUri = ResourceServerUri;

                return response;
            }
        }

    }
}
    
