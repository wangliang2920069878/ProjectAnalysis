|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AuthorizationHeaderExtensions](#authorizationheaderextensions)
* [HttpClientDeviceFlowExtensions](#httpclientdeviceflowextensions)
* [HttpClientDiscoveryExtensions](#httpclientdiscoveryextensions)
* [HttpClientDynamicRegistrationExtensions](#httpclientdynamicregistrationextensions)
* [HttpClientJsonWebKeySetExtensions](#httpclientjsonWebkeysetextensions)
* [HttpClientTokenIntrospectionExtensions](#httpclienttokenIntrospectionextensions)
* [HttpClientTokenRequestExtensions](#httpclienttokenrequestextensions)
* [HttpClientTokenRevocationExtensions](#httpclienttokenrevocationextensions)
* [HttpClientUserInfoExtensions](#httpclientuserinfoextensions)
* [JObjectExtensions](#jObjectextensions)
* [RequestUrlExtensions](#requesturlextensions)
```
    /// <summary>
    /// HttpRequestMessage的扩展
    /// </summary>
    public static class AuthorizationHeaderExtensions
    {
        /// <summary>
        /// 设置基本身份验证标头。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password.</param>
        public static void SetBasicAuthentication(this HttpClient client, string userName, string password)
        {
            client.DefaultRequestHeaders.Authorization = new BasicAuthenticationHeaderValue(userName, password);
        }

        /// <summary>
        /// 为RFC6749客户端身份验证设置基本身份验证标头。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password.</param>
        public static void SetBasicAuthenticationOAuth(this HttpClient client, string userName, string password)
        {
            client.DefaultRequestHeaders.Authorization = new BasicAuthenticationOAuthHeaderValue(userName, password);
        }

        /// <summary>
        /// 设置具有给定方案和值的授权标头。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="scheme">The scheme.</param>
        /// <param name="token">The token.</param>
        public static void SetToken(this HttpClient client, string scheme, string token)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(scheme, token);
        }

        /// <summary>
        /// 设置带有承载令牌的授权标头。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="token">The token.</param>
        public static void SetBearerToken(this HttpClient client, string token)
        {
            client.SetToken("Bearer", token);
        }

        /// <summary>
        ///设置基本身份验证标头。
        /// </summary>
        /// <param name="request">The HTTP request message.</param>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password.</param>
        public static void SetBasicAuthentication(this HttpRequestMessage request, string userName, string password)
        {
            request.Headers.Authorization = new BasicAuthenticationHeaderValue(userName, password);
        }
        
        /// <summary>
        ///为RFC6749客户端身份验证设置基本身份验证标头。
        /// </summary>
        /// <param name="request">The HTTP request message.</param>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password.</param>
        public static void SetBasicAuthenticationOAuth(this HttpRequestMessage request, string userName, string password)
        {
            request.Headers.Authorization = new BasicAuthenticationOAuthHeaderValue(userName, password);
        }

        /// <summary>
        /// 设置具有给定方案和值的授权标头。
        /// </summary>
        /// <param name="request">The HTTP request message.</param>
        /// <param name="scheme">The scheme.</param>
        /// <param name="token">The token.</param>
        public static void SetToken(this HttpRequestMessage request, string scheme, string token)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(scheme, token);
        }

        /// <summary>
        ///设置带有承载令牌的授权标头。
        /// </summary>
        /// <param name="request">The HTTP request message.</param>
        /// <param name="token">The token.</param>
        public static void SetBearerToken(this HttpRequestMessage request, string token)
        {
            request.SetToken("Bearer", token);
        }
    }
```
### HttpClientDeviceFlowExtensions
```
    /// <summary>
    ///OIDC userinfo的HttpClient扩展
    /// </summary>
    public static class HttpClientDeviceFlowExtensions
    {
        /// <summary>
        /// 发送一个userinfo请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<DeviceAuthorizationResponse> RequestDeviceAuthorizationAsync(this HttpMessageInvoker client, DeviceAuthorizationRequest request, CancellationToken cancellationToken = default)
        {
            var clone = request.Clone();

            clone.Parameters.AddOptional(OidcConstants.AuthorizeRequest.Scope, request.Scope);
            clone.Method = HttpMethod.Post;
            clone.Prepare();
                        
            HttpResponseMessage response;
            try
            {
                response = await client.SendAsync(clone, cancellationToken).ConfigureAwait();
            }
            catch (Exception ex)
            {
                return ProtocolResponse.FromException<DeviceAuthorizationResponse>(ex);
            }

            return await ProtocolResponse.FromHttpResponseAsync<DeviceAuthorizationResponse>(response).ConfigureAwait();
        }
    }
```
### HttpClientDiscoveryExtensions
```
    /// <summary>
    /// 用于OIDC发现的HttpClient扩展
    /// </summary>
    public static class HttpClientDiscoveryExtensions
    {
        /// <summary>
        /// 发送发现文件请求
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="address">The address.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<DiscoveryDocumentResponse> GetDiscoveryDocumentAsync(this HttpClient client, string address = null, CancellationToken cancellationToken = default)
        {
            return await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest { Address = address }, cancellationToken).ConfigureAwait();
        }

        /// <summary>
        /// 发送发现文件请求
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<DiscoveryDocumentResponse> GetDiscoveryDocumentAsync(this HttpMessageInvoker client, DiscoveryDocumentRequest request, CancellationToken cancellationToken = default)
        {
            string address;
            if (request.Address.IsPresent())
            {
                address = request.Address;
            }
            else if (client is HttpClient)
            {
                address = ((HttpClient)client).BaseAddress.AbsoluteUri;
            }
            else
            {
                throw new ArgumentException("An address is required.");
            }

            var parsed = DiscoveryEndpoint.ParseUrl(address);
            var authority = parsed.Authority;
            var url = parsed.Url;

            if (request.Policy.Authority.IsMissing())
            {
                request.Policy.Authority = authority;
            }

            string jwkUrl = "";

            if (!DiscoveryEndpoint.IsSecureScheme(new Uri(url), request.Policy))
            {
                return ProtocolResponse.FromException<DiscoveryDocumentResponse>(new InvalidOperationException("HTTPS required"), $"Error connecting to {url}. HTTPS required.");
            }

            try
            {
                var clone = request.Clone();

                clone.Method = HttpMethod.Get;
                clone.Prepare();

                clone.RequestUri = new Uri(url);

                var response = await client.SendAsync(clone, cancellationToken).ConfigureAwait();

                string responseContent = null;

                if (response.Content != null)
                {
                    responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait();
                }

                if (!response.IsSuccessStatusCode)
                {
                    return await ProtocolResponse.FromHttpResponseAsync<DiscoveryDocumentResponse>(response, $"Error connecting to {url}: {response.ReasonPhrase}");
                }

                var disco = await ProtocolResponse.FromHttpResponseAsync<DiscoveryDocumentResponse>(response, request.Policy).ConfigureAwait();

                if (disco.IsError)
                {
                    return disco;
                }

                try
                {
                    jwkUrl = disco.JwksUri;
                    if (jwkUrl != null)
                    {
                        var jwkClone = request.Clone<JsonWebKeySetRequest>();
                        jwkClone.Method = HttpMethod.Get;
                        jwkClone.Address = jwkUrl;
                        jwkClone.Prepare();

                        var jwkResponse = await client.GetJsonWebKeySetAsync(jwkClone, cancellationToken).ConfigureAwait();

                        if (jwkResponse.IsError)
                        {
                            return await ProtocolResponse.FromHttpResponseAsync<DiscoveryDocumentResponse>(jwkResponse.HttpResponse, $"Error connecting to {jwkUrl}: {jwkResponse.HttpErrorReason}").ConfigureAwait();
                        }

                        disco.KeySet = jwkResponse.KeySet;
                    }

                    return disco;
                }
                catch (Exception ex)
                {
                    return ProtocolResponse.FromException<DiscoveryDocumentResponse>(ex, $"Error connecting to {jwkUrl}. {ex.Message}.");
                }
            }
            catch (Exception ex)
            {
                return ProtocolResponse.FromException<DiscoveryDocumentResponse>(ex, $"Error connecting to {url}. {ex.Message}.");
            }
        }
    }
```
### HttpClientDynamicRegistrationExtensions
```
    /// <summary>
    /// 动态注册的HttpClient扩展
    /// </summary>
    public static class HttpClientDynamicRegistrationExtensions
    {
        /// <summary>
        ///发送动态注册请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<DynamicClientRegistrationResponse> RegisterClientAsync(this HttpMessageInvoker client, DynamicClientRegistrationRequest request, CancellationToken cancellationToken = default)
        {
            var clone = request.Clone();

            clone.Method = HttpMethod.Post;
            clone.Content = new StringContent(JsonConvert.SerializeObject(request.Document), Encoding.UTF8, "application/json");
            clone.Prepare();

            if (request.Token.IsPresent())
            {
                clone.SetBearerToken(request.Token);
            }

            HttpResponseMessage response;
            try
            {
                response = await client.SendAsync(clone, cancellationToken).ConfigureAwait();
            }
            catch (Exception ex)
            {
                return ProtocolResponse.FromException<DynamicClientRegistrationResponse>(ex);
            }

            return await ProtocolResponse.FromHttpResponseAsync<DynamicClientRegistrationResponse>(response).ConfigureAwait();
        }
    }
```
### HttpClientJsonWebKeySetExtensions
```
    /// <summary>
    /// 用于OIDC发现的HttpClient扩展
    /// </summary>
    public static class HttpClientJsonWebKeySetExtensions
    {
        /// <summary>
        /// 发送JSON Web密钥集文档请求
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="address"></param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<JsonWebKeySetResponse> GetJsonWebKeySetAsync(this HttpMessageInvoker client, string address = null, CancellationToken cancellationToken = default)
        {
            return await client.GetJsonWebKeySetAsync(new JsonWebKeySetRequest
            {
                Address = address
            }, cancellationToken).ConfigureAwait();
        }

        /// <summary>
        /// 发送JSON Web密钥集文档请求
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<JsonWebKeySetResponse> GetJsonWebKeySetAsync(this HttpMessageInvoker client, JsonWebKeySetRequest request, CancellationToken cancellationToken = default)
        {
            var clone = request.Clone();

            clone.Method = HttpMethod.Get;
            clone.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/jwk-set+json"));
            clone.Prepare();

            HttpResponseMessage response;

            try
            {
                response = await client.SendAsync(clone, cancellationToken).ConfigureAwait();

                string responseContent = null;
                if (response.Content != null)
                {
                    responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait();
                }

                if (!response.IsSuccessStatusCode)
                {
                    return await ProtocolResponse.FromHttpResponseAsync<JsonWebKeySetResponse>(response, $"Error connecting to {clone.RequestUri.AbsoluteUri}: {response.ReasonPhrase}").ConfigureAwait();
                }
            }
            catch (Exception ex)
            {
                return ProtocolResponse.FromException<JsonWebKeySetResponse>(ex, $"Error connecting to {clone.RequestUri.AbsoluteUri}. {ex.Message}.");
            }

            return await ProtocolResponse.FromHttpResponseAsync<JsonWebKeySetResponse>(response);
        }
    }
```
### HttpClientTokenIntrospectionExtensions
```
    /// <summary>
    /// OAuth令牌自省的HttpClient扩展
    /// </summary>
    public static class HttpClientTokenIntrospectionExtensions
    {
        /// <summary>
        /// 发送OAuth令牌自省请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<TokenIntrospectionResponse> IntrospectTokenAsync(this HttpMessageInvoker client, TokenIntrospectionRequest request, CancellationToken cancellationToken = default)
        {
            var clone = request.Clone();

            clone.Method = HttpMethod.Post;
            clone.Parameters.AddRequired(OidcConstants.TokenIntrospectionRequest.Token, request.Token);
            clone.Parameters.AddOptional(OidcConstants.TokenIntrospectionRequest.TokenTypeHint, request.TokenTypeHint);
            clone.Prepare();

            HttpResponseMessage response;
            try
            {
                response = await client.SendAsync(clone, cancellationToken).ConfigureAwait();
            }
            catch (Exception ex)
            {
                return ProtocolResponse.FromException<TokenIntrospectionResponse>(ex);
            }

            return await ProtocolResponse.FromHttpResponseAsync<TokenIntrospectionResponse>(response).ConfigureAwait();
        }
    }
```
### HttpClientTokenRequestExtensions
```
    /// <summary>
    /// OAuth令牌请求的HttpClient扩展
    /// </summary>
    public static class HttpClientTokenRequestExtensions
    {
        /// <summary>
        /// 使用client_credentials授予类型发送令牌请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<TokenResponse> RequestClientCredentialsTokenAsync(this HttpMessageInvoker client, ClientCredentialsTokenRequest request, CancellationToken cancellationToken = default)
        {
            var clone = request.Clone();

            clone.Parameters.AddRequired(OidcConstants.TokenRequest.GrantType, OidcConstants.GrantTypes.ClientCredentials);
            clone.Parameters.AddOptional(OidcConstants.TokenRequest.Scope, request.Scope);

            return await client.RequestTokenAsync(clone, cancellationToken).ConfigureAwait();
        }

        /// <summary>
        ///使用urn：ietf：params：oauth：grant-type：device_code授予类型发送令牌请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<TokenResponse> RequestDeviceTokenAsync(this HttpMessageInvoker client, DeviceTokenRequest request, CancellationToken cancellationToken = default)
        {
            var clone = request.Clone();

            clone.Parameters.AddRequired(OidcConstants.TokenRequest.GrantType, OidcConstants.GrantTypes.DeviceCode);
            clone.Parameters.AddRequired(OidcConstants.TokenRequest.DeviceCode, request.DeviceCode);

            return await client.RequestTokenAsync(clone, cancellationToken).ConfigureAwait();
        }

        /// <summary>
        /// 使用密码授予类型发送令牌请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<TokenResponse> RequestPasswordTokenAsync(this HttpMessageInvoker client, PasswordTokenRequest request, CancellationToken cancellationToken = default)
        {
            var clone = request.Clone();

            clone.Parameters.AddRequired(OidcConstants.TokenRequest.GrantType, OidcConstants.GrantTypes.Password);
            clone.Parameters.AddRequired(OidcConstants.TokenRequest.UserName, request.UserName);
            clone.Parameters.AddRequired(OidcConstants.TokenRequest.Password, request.Password, allowEmpty: true);
            clone.Parameters.AddOptional(OidcConstants.TokenRequest.Scope, request.Scope);

            return await client.RequestTokenAsync(clone, cancellationToken).ConfigureAwait();
        }

        /// <summary>
        /// 使用authorization_code授权类型发送令牌请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<TokenResponse> RequestAuthorizationCodeTokenAsync(this HttpMessageInvoker client, AuthorizationCodeTokenRequest request, CancellationToken cancellationToken = default)
        {
            var clone = request.Clone();

            clone.Parameters.AddRequired(OidcConstants.TokenRequest.GrantType, OidcConstants.GrantTypes.AuthorizationCode);
            clone.Parameters.AddRequired(OidcConstants.TokenRequest.Code, request.Code);
            clone.Parameters.AddRequired(OidcConstants.TokenRequest.RedirectUri, request.RedirectUri);
            clone.Parameters.AddOptional(OidcConstants.TokenRequest.CodeVerifier, request.CodeVerifier);

            return await client.RequestTokenAsync(clone, cancellationToken).ConfigureAwait();
        }

        /// <summary>
        /// 使用refresh_token授权类型发送令牌请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<TokenResponse> RequestRefreshTokenAsync(this HttpMessageInvoker client, RefreshTokenRequest request, CancellationToken cancellationToken = default)
        {
            var clone = request.Clone();

            clone.Parameters.AddRequired(OidcConstants.TokenRequest.GrantType, OidcConstants.GrantTypes.RefreshToken);
            clone.Parameters.AddRequired(OidcConstants.TokenRequest.RefreshToken, request.RefreshToken);
            clone.Parameters.AddOptional(OidcConstants.TokenRequest.Scope, request.Scope);

            return await client.RequestTokenAsync(clone, cancellationToken).ConfigureAwait();
        }

        /// <summary>
        ///发送令牌请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<TokenResponse> RequestTokenAsync(this HttpMessageInvoker client, TokenRequest request, CancellationToken cancellationToken = default)
        {
            var clone = request.Clone();

            if (!clone.Parameters.ContainsKey(OidcConstants.TokenRequest.GrantType))
            {
                clone.Parameters.AddRequired(OidcConstants.TokenRequest.GrantType, request.GrantType);
            }

            return await client.RequestTokenAsync(clone, cancellationToken).ConfigureAwait();
        }

        /// <summary>
        /// 发送令牌请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="address">The address.</param>
        /// <param name="parameters">The parameters.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">parameters</exception>
        public static async Task<TokenResponse> RequestTokenRawAsync(this HttpMessageInvoker client, string address, IDictionary<string, string> parameters, CancellationToken cancellationToken = default)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));

            var request = new TokenRequest()
            {
                Address = address,
                Parameters = parameters
            };

            return await client.RequestTokenAsync(request, cancellationToken).ConfigureAwait();
        }

        internal static async Task<TokenResponse> RequestTokenAsync(this HttpMessageInvoker client, ProtocolRequest request, CancellationToken cancellationToken = default)
        {
            request.Prepare();
            request.Method = HttpMethod.Post;
            
            HttpResponseMessage response;
            try
            {
                response = await client.SendAsync(request, cancellationToken).ConfigureAwait();
            }
            catch (Exception ex)
            {
                return ProtocolResponse.FromException<TokenResponse>(ex);
            }

            return await ProtocolResponse.FromHttpResponseAsync<TokenResponse>(response).ConfigureAwait();
        }
    }
```
### HttpClientTokenRevocationExtensions
```
    /// <summary>
    ///用于OAuth令牌吊销的HttpClient扩展
    /// </summary>
    public static class HttpClientTokenRevocationExtensions
    {
        /// <summary>
        /// 发送OAuth令牌吊销请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<TokenRevocationResponse> RevokeTokenAsync(this HttpMessageInvoker client, TokenRevocationRequest request, CancellationToken cancellationToken = default)
        {
            var clone = request.Clone();

            clone.Method = HttpMethod.Post;
            clone.Parameters.AddRequired(OidcConstants.TokenIntrospectionRequest.Token, request.Token);
            clone.Parameters.AddOptional(OidcConstants.TokenIntrospectionRequest.TokenTypeHint, request.TokenTypeHint);
            clone.Prepare();

            HttpResponseMessage response;
            try
            {
                response = await client.SendAsync(clone, cancellationToken).ConfigureAwait();
            }
            catch (Exception ex)
            {
                return ProtocolResponse.FromException<TokenRevocationResponse>(ex);
            }

            return await ProtocolResponse.FromHttpResponseAsync<TokenRevocationResponse>(response).ConfigureAwait();
        }
    }
```
### HttpClientUserInfoExtensions
```
    /// <summary>
    /// OIDC userinfo的HttpClient扩展
    /// </summary>
    public static class HttpClientUserInfoExtensions
    {
        /// <summary>
        /// 发送一个userinfo请求。
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="request">The request.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public static async Task<UserInfoResponse> GetUserInfoAsync(this HttpMessageInvoker client, UserInfoRequest request, CancellationToken cancellationToken = default)
        {
            if (request.Token.IsMissing()) throw new ArgumentNullException(nameof(request.Token));

            var clone = request.Clone();

            clone.Method = HttpMethod.Get;
            clone.SetBearerToken(request.Token);
            clone.Prepare();

            HttpResponseMessage response;
            try
            {
                response = await client.SendAsync(clone, cancellationToken).ConfigureAwait();
            }
            catch (Exception ex)
            {
                return ProtocolResponse.FromException<UserInfoResponse>(ex);
            }

            return await ProtocolResponse.FromHttpResponseAsync<UserInfoResponse>(response).ConfigureAwait();
        }
    }
```
### JObjectExtensions
```
    /// <summary>
    /// JObject的扩展
    /// </summary>
    public static class JObjectExtensions
    {
        /// <summary>
        /// 将JSON声明对象转换为Claim列表
        /// </summary>
        /// <param name="json">The json.</param>
        /// <param name="excludeKeys">Claims that should be excluded.</param>
        /// <returns></returns>
        public static IEnumerable<Claim> ToClaims(this JObject json, params string[] excludeKeys)
        {
            var claims = new List<Claim>();
            var excludeList = excludeKeys.ToList();

            foreach (var x in json)
            {
                if (excludeList.Contains(x.Key)) continue;

                if (x.Value is JArray array)
                {
                    foreach (var item in array)
                    {
                        claims.Add(new Claim(x.Key, Stringify(item)));
                    }
                }
                else
                {
                    claims.Add(new Claim(x.Key, Stringify(x.Value)));
                }
            }

            return claims;
        }

        private static string Stringify(JToken item)
        {
            // 字符串是特殊的，因为item.ToString（Formatting.None）将导致“ /” string /“”。 引号将被添加。
             //布尔值需要item.ToString否则为'true'=>'True'
            var value = item.Type == JTokenType.String ?
                item.ToString() :
                item.ToString(Newtonsoft.Json.Formatting.None);

            return value;
        }

        /// <summary>
        /// 尝试从JObject获取值
        /// </summary>
        /// <param name="json">The json.</param>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        public static JToken TryGetValue(this JObject json, string name)
        {
            if (json != null && json.TryGetValue(name, StringComparison.OrdinalIgnoreCase, out JToken value))
            {
                return value;
            }

            return null;
        }

        /// <summary>
        /// 尝试从JObject获取一个int
        /// </summary>
        /// <param name="json">The json.</param>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        public static int? TryGetInt(this JObject json, string name)
        {
            var value = json.TryGetString(name);

            if (value != null)
            {
                if (int.TryParse(value, out int intValue))
                {
                    return intValue;
                }
            }

            return null;
        }

        /// <summary>
        ///尝试从JObject获取字符串
        /// </summary>
        /// <param name="json">The json.</param>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        public static string TryGetString(this JObject json, string name)
        {
            JToken value = json.TryGetValue(name);
            return value?.ToString();
        }

        /// <summary>
        /// 尝试从JObject获取布尔值
        /// </summary>
        /// <param name="json">The json.</param>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        public static bool? TryGetBoolean(this JObject json, string name)
        {
            var value = json.TryGetString(name);

            if (bool.TryParse(value, out bool result))
            {
                return result;
            }

            return null;
        }

        /// <summary>
        /// 尝试从JObject获取字符串数组
        /// </summary>
        /// <param name="json">The json.</param>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        public static IEnumerable<string> TryGetStringArray(this JObject json, string name)
        {
            var values = new List<string>();

            if (json.TryGetValue(name) is JArray array)
            {
                foreach (var item in array)
                {
                    values.Add(item.ToString());
                }
            }

            return values;
        }
    }
```
### RequestUrlExtensions
```
    /// <summary>
    /// RequestUrl的扩展
    /// </summary>
    public static class RequestUrlExtensions
    {
        /// <summary>
        /// 创建一个授权URL。
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="values">The values (either using a string Dictionary or an object's properties).</param>
        /// <returns></returns>
        public static string Create(this RequestUrl request, object values)
        {
            return request.Create(ValuesHelper.ObjectToDictionary(values));
        }

        /// <summary>
        /// 创建一个授权URL。
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="responseType">The response type.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="state">The state.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="loginHint">The login hint.</param>
        /// <param name="acrValues">The acr values.</param>
        /// <param name="prompt">The prompt.</param>
        /// <param name="responseMode">The response mode.</param>
        /// <param name="codeChallenge">The code challenge.</param>
        /// <param name="codeChallengeMethod">The code challenge method.</param>
        /// <param name="display">The display option.</param>
        /// <param name="maxAge">The max age.</param>
        /// <param name="uiLocales">The ui locales.</param>
        /// <param name="idTokenHint">The id_token hint.</param>
        /// <param name="extra">Extra parameters.</param>
        /// <returns></returns>
        public static string CreateAuthorizeUrl(this RequestUrl request,
            string clientId,
            string responseType,
            string scope = null,
            string redirectUri = null,
            string state = null,
            string nonce = null,
            string loginHint = null,
            string acrValues = null,
            string prompt = null,
            string responseMode = null,
            string codeChallenge = null,
            string codeChallengeMethod = null,
            string display = null,
            int? maxAge = null,
            string uiLocales = null,
            string idTokenHint = null,
            object extra = null)
        {
            var values = new Dictionary<string, string>
            {
                { OidcConstants.AuthorizeRequest.ClientId, clientId },
                { OidcConstants.AuthorizeRequest.ResponseType, responseType }
            };

            values.AddOptional(OidcConstants.AuthorizeRequest.Scope, scope);
            values.AddOptional(OidcConstants.AuthorizeRequest.RedirectUri, redirectUri);
            values.AddOptional(OidcConstants.AuthorizeRequest.State, state);
            values.AddOptional(OidcConstants.AuthorizeRequest.Nonce, nonce);
            values.AddOptional(OidcConstants.AuthorizeRequest.LoginHint, loginHint);
            values.AddOptional(OidcConstants.AuthorizeRequest.AcrValues, acrValues);
            values.AddOptional(OidcConstants.AuthorizeRequest.Prompt, prompt);
            values.AddOptional(OidcConstants.AuthorizeRequest.ResponseMode, responseMode);
            values.AddOptional(OidcConstants.AuthorizeRequest.CodeChallenge, codeChallenge);
            values.AddOptional(OidcConstants.AuthorizeRequest.CodeChallengeMethod, codeChallengeMethod);
            values.AddOptional(OidcConstants.AuthorizeRequest.Display, display);
            values.AddOptional(OidcConstants.AuthorizeRequest.MaxAge, maxAge?.ToString());
            values.AddOptional(OidcConstants.AuthorizeRequest.UiLocales, uiLocales);
            values.AddOptional(OidcConstants.AuthorizeRequest.IdTokenHint, idTokenHint);

            return request.Create(ValuesHelper.Merge(values, ValuesHelper.ObjectToDictionary(extra)));
        }

        /// <summary>
        /// 创建一个end_session URL。
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="idTokenHint">The id_token hint.</param>
        /// <param name="postLogoutRedirectUri">The post logout redirect URI.</param>
        /// <param name="state">The state.</param>
        /// <param name="extra">The extra parameters.</param>
        /// <returns></returns>
        public static string CreateEndSessionUrl(this RequestUrl request,
            string idTokenHint = null,
            string postLogoutRedirectUri = null,
            string state = null,
            object extra = null)
        {
            var values = new Dictionary<string, string>();

            values.AddOptional(OidcConstants.EndSessionRequest.IdTokenHint, idTokenHint);
            values.AddOptional(OidcConstants.EndSessionRequest.PostLogoutRedirectUri, postLogoutRedirectUri);
            values.AddOptional(OidcConstants.EndSessionRequest.State, state);

            return request.Create(ValuesHelper.Merge(values, ValuesHelper.ObjectToDictionary(extra)));
        }
    }
```