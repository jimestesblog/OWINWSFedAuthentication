using Newtonsoft.Json;

namespace OAuth2SAMLGrant.Model
{
    class OAuthToken
    {
        private string _errorMessage;
        private bool _hasError;
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }

        [JsonProperty("expires_in")]
        public string ExpiresIn { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        public string OAuthEndpointUri { get; set; }

        public string ResourceServerUri { get; set; }
        public bool hasError { get { return this._hasError; } }
        public string errorMessage { get { return this._errorMessage; } }
        public void setError(string errorMessage)
        {
            _errorMessage = errorMessage;
            _hasError = true;
        }
    }
}
