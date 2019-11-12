|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AuthorizeResponse](#authorizeresponse)
* [ProtocolRequest](#protocolrequest)
* [ProtocolResponse](#protocolresponse)
* [ResponseErrorType](#responseerrortype)
* [DeviceAuthorizationRequest](#deviceauthorizationrequest)
* [DeviceAuthorizationResponse](#deviceauthorizationresponse)
* [DiscoveryDocumentRequest](#discoverydocumentrequest)
* [DiscoveryDocumentResponse](#discoverydocumentresponse)
* [DynamicClientRegistrationDocument](#dynamicclientregistrationdocument)
* [DynamicClientRegistrationRequest](#dynamicclientRegistrationrequest)
* [DynamicClientRegistrationResponse](#dynamicclientregistrationresponse)
* [JsonWebKeySetRequest](#jsonWebKeysetrequest)
* [JsonWebKeySetResponse](#jsonwebkeysetresponse)
* [TokenIntrospectionRequest](#tokenintrospectionrequest)
* [TokenIntrospectionResponse](#tokenintrospectionresponse)
* [TokenRequest](#tokenrequest)
* [TokenResponse](#tokenresponse)
* [TokenRevocationRequest](#tokenrevocationrequest)
* [TokenRevocationResponse](#tokenrevocationresponse)
* [UserInfoRequest](#userinforequest)
* [UserInfoResponse](#userinforesponse)
### AuthorizeResponse
```
    /// <summary>
    ///模拟授权请求的响应
    /// </summary>
    public class AuthorizeResponse
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizeResponse"/> class.
        /// </summary>
        /// <param name="raw">原始响应网址.</param>
        public AuthorizeResponse(string raw)
        {
            Raw = raw;
            ParseRaw();
        }

        /// <summary>
        /// 获取原始响应URL。
        /// </summary>
        /// <value>
        /// The raw.
        /// </value>
        public string Raw { get; }

        /// <summary>
        /// 获取响应的键/值对。
        /// </summary>
        /// <value>
        /// The values.
        /// </value>
        public Dictionary<string, string> Values { get; } = new Dictionary<string, string>();

        /// <summary>
        /// 获取授权码。
        /// </summary>
        /// <value>
        /// The authorization code.
        /// </value>
        public string Code => TryGet(OidcConstants.AuthorizeResponse.Code);

        /// <summary>
        /// 获取访问令牌。
        /// </summary>
        /// <value>
        /// The access token.
        /// </value>
        public string AccessToken => TryGet(OidcConstants.AuthorizeResponse.AccessToken);

        /// <summary>
        /// 获取身份令牌。
        /// </summary>
        /// <value>
        /// The identity token.
        /// </value>
        public string IdentityToken => TryGet(OidcConstants.AuthorizeResponse.IdentityToken);

        /// <summary>
        ///获取错误。
        /// </summary>
        /// <value>
        /// The error.
        /// </value>
        public string Error => TryGet(OidcConstants.AuthorizeResponse.Error);

        /// <summary>
        /// 获取范围。
        /// </summary>
        /// <value>
        /// The scope.
        /// </value>
        public string Scope => TryGet(OidcConstants.AuthorizeResponse.Scope);

        /// <summary>
        /// 获取令牌的类型。
        /// </summary>
        /// <value>
        /// The type of the token.
        /// </value>
        public string TokenType => TryGet(OidcConstants.AuthorizeResponse.TokenType);

        /// <summary>
        /// 获取状态。
        /// </summary>
        /// <value>
        /// The state.
        /// </value>
        public string State => TryGet(OidcConstants.AuthorizeResponse.State);

        /// <summary>
        ///获取错误描述。
        /// </summary>
        /// <value>
        /// The error description.
        /// </value>
        public string ErrorDescription => TryGet(OidcConstants.AuthorizeResponse.ErrorDescription);

        /// <summary>
        /// 获取一个值，该值指示响应是否为错误。
        /// </summary>
        /// <value>
        ///   <c>true</c> if the response is an error; otherwise, <c>false</c>.
        /// </value>
        public bool IsError => Error.IsPresent();

        /// <summary>
        /// 获取到期时间。
        /// </summary>
        /// <value>
        /// The expires in.
        /// </value>
        public int ExpiresIn
        {
            get
            {
                var value = TryGet(OidcConstants.AuthorizeResponse.ExpiresIn);
                int.TryParse(value, out var theValue);

                return theValue;
            }
        }

        private void ParseRaw()
        {
            string[] fragments;

            // query string encoded
            if (Raw.Contains("?"))
            {
                fragments = Raw.Split('?');

                var additionalHashFragment = fragments[1].IndexOf('#');
                if (additionalHashFragment >= 0)
                {
                    fragments[1] = fragments[1].Substring(0, additionalHashFragment);
                }
            }
            // fragment encoded
            else if (Raw.Contains("#"))
            {
                fragments = Raw.Split('#');
            }
            // form encoded
            else
            {
                fragments = new[] { "", Raw };
            }

            var qparams = fragments[1].Split('&');

            foreach (var param in qparams)
            {
                var parts = param.Split('=');

                if (parts.Length == 2)
                {
                    Values.Add(parts[0], parts[1]);
                }
                else
                {
                    throw new InvalidOperationException("Malformed callback URL.");
                }
            }
        }

        /// <summary>
        /// 尝试获取值。
        /// </summary>
        /// <param name="type">The type.</param>
        /// <returns></returns>
        public string TryGet(string type)
        {
            if (Values.TryGetValue(type, out var value))
            {
                return WebUtility.UrlDecode(value);
            }

            return null;
        }
    }
```
### ProtocolRequest
```
    /// <summary>
    /// 使用客户端凭证为基本OAuth / OIDC请求建模
    /// </summary>
    public class ProtocolRequest : HttpRequestMessage
    {
        /// <summary>
        /// 初始化HTTP协议请求并将accept标头设置为application / json
        /// </summary>
        public ProtocolRequest()
        {
            Headers.Accept.Clear();
            Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        /// <summary>
        /// 获取或设置端点地址（您也可以设置RequestUri或留空以使用HttpClient基址）。
        /// </summary>
        /// <value>
        /// The address.
        /// </value>
        public string Address { get; set; }

        /// <summary>
        /// 获取或设置客户端标识符。
        /// </summary>
        /// <value>
        /// The client identifier.
        /// </value>
        public string ClientId { get; set; }

        /// <summary>
        /// 获取或设置客户端机密。
        /// </summary>
        /// <value>
        /// The client secret.
        /// </value>
        public string ClientSecret { get; set; }

        /// <summary>
        /// 获取或设置客户端断言。
        /// </summary>
        /// <value>
        /// The assertion.
        /// </value>
        public ClientAssertion ClientAssertion { get; set; } = new ClientAssertion();

        /// <summary>
        /// 获取或设置客户端凭据样式（帖子正文与授权标头）。
        /// </summary>
        /// <value>
        /// The client credential style.
        /// </value>
        public ClientCredentialStyle ClientCredentialStyle { get; set; } = ClientCredentialStyle.PostBody;

        /// <summary>
        /// 获取或设置基本身份验证标头样式（经典HTTP与OAuth 2）。
        /// </summary>
        /// <value>
        /// The basic authentication header style.
        /// </value>
        public BasicAuthenticationHeaderStyle AuthorizationHeaderStyle { get; set; } = BasicAuthenticationHeaderStyle.Rfc6749;

        /// <summary>
        ///获取或设置其他协议参数。
        /// </summary>
        /// <value>
        /// The parameters.
        /// </value>
        public IDictionary<string, string> Parameters { get; set; } = new Dictionary<string, string>();

        /// <summary>
        ///克隆此实例。
        /// </summary>
        public ProtocolRequest Clone()
        {
            return Clone<ProtocolRequest>();
        }

        /// <summary>
        /// Clones this instance.
        /// </summary>
        public T Clone<T>()
            where T: ProtocolRequest, new()
        {
            var clone = new T
            {
                RequestUri = RequestUri,
                Version = Version,
                Method = Method,

                Address = Address,
                AuthorizationHeaderStyle = AuthorizationHeaderStyle,
                ClientAssertion = ClientAssertion,
                ClientCredentialStyle = ClientCredentialStyle,
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                Parameters = new Dictionary<string, string>(),
            };

            if (Parameters != null)
            {
                foreach (var item in Parameters) clone.Parameters.Add(item);
            }

            clone.Headers.Clear();
            foreach (var header in Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (Properties != null && Properties.Any())
            {
                foreach (var property in Properties)
                {
                    clone.Properties.Add(property);
                }
            }

            return clone;
        }

        /// <summary>
        /// 将协议参数应用于HTTP请求
        /// </summary>
        public void Prepare()
        {
            if (ClientId.IsPresent())
            {
                if (ClientCredentialStyle == ClientCredentialStyle.AuthorizationHeader)
                {
                    if (AuthorizationHeaderStyle == BasicAuthenticationHeaderStyle.Rfc6749)
                    {
                        this.SetBasicAuthenticationOAuth(ClientId, ClientSecret ?? "");
                    }
                    else if (AuthorizationHeaderStyle == BasicAuthenticationHeaderStyle.Rfc2617)
                    {
                        this.SetBasicAuthentication(ClientId, ClientSecret ?? "");
                    }
                    else
                    {
                        throw new InvalidOperationException("Unsupported basic authentication header style");
                    }
                }
                else if (ClientCredentialStyle == ClientCredentialStyle.PostBody)
                {
                    Parameters.AddRequired(OidcConstants.TokenRequest.ClientId, ClientId);
                    Parameters.AddOptional(OidcConstants.TokenRequest.ClientSecret, ClientSecret);
                }
                else
                {
                    throw new InvalidOperationException("Unsupported client credential style");
                }
            }

            if (ClientAssertion != null)
            {
                if (ClientAssertion.Type != null && ClientAssertion.Value != null)
                {
                    Parameters.AddOptional(OidcConstants.TokenRequest.ClientAssertionType, ClientAssertion.Type);
                    Parameters.AddOptional(OidcConstants.TokenRequest.ClientAssertion, ClientAssertion.Value);
                }
            }

            if (Address.IsPresent())
            {
                RequestUri = new Uri(Address);
            }

            if (Parameters.Any())
            {
                Content = new FormUrlEncodedContent(Parameters);
            }
        }
    }

    /// <summary>
    /// 为客户断言建模
    /// </summary>
    public class ClientAssertion
    {
        /// <summary>
        /// 获取或设置断言类型。
        /// </summary>
        /// <value>
        /// The type.
        /// </value>
        public string Type { get; set; }

        /// <summary>
        /// 获取或设置断言值。
        /// </summary>
        /// <value>
        /// The value.
        /// </value>
        public string Value { get; set; }
    }
```
### ProtocolResponse
```
    /// <summary>
    /// 协议响应
    /// </summary>
    public class ProtocolResponse
    {
        /// <summary>
        /// Initializes a protocol response from an HTTP response
        /// </summary>
        /// <typeparam name="T">特定协议响应类型</typeparam>
        /// <param name="httpResponse">HTTP响应.</param>
        /// <param name="initializationData">初始化数据。</param>
        /// <returns></returns>
        public static async Task<T> FromHttpResponseAsync<T>(HttpResponseMessage httpResponse, object initializationData = null) where T: ProtocolResponse, new()
        {
            var response = new T
            {
                HttpResponse = httpResponse
            };

            // try to read content
            string content = null;
            try
            {
                content = await httpResponse.Content.ReadAsStringAsync().ConfigureAwait();
                response.Raw = content;
            }
            catch { }

            // 一些HTTP错误-尝试将主体解析为JSON，但也允许使用非JSON
            if (httpResponse.IsSuccessStatusCode == false &&
                httpResponse.StatusCode != HttpStatusCode.BadRequest)
            {
                response.ErrorType = ResponseErrorType.Http;

                if (content.IsPresent())
                {
                    try
                    {
                        response.Json = JObject.Parse(content);
                    }
                    catch { }
                }

                await response.InitializeAsync(initializationData).ConfigureAwait();
                return response;
            }
            
            if (httpResponse.StatusCode == HttpStatusCode.BadRequest)
            {
                response.ErrorType = ResponseErrorType.Protocol;
            }

            // either 200 or 400 - both cases need a JSON response (if present), otherwise error
            try
            {
                if (content.IsPresent())
                {
                    response.Json = JObject.Parse(content);
                }
            }
            catch (Exception ex)
            {
                response.ErrorType = ResponseErrorType.Exception;
                response.Exception = ex;
            }

            await response.InitializeAsync(initializationData).ConfigureAwait();
            return response;
        }

        /// <summary>
        /// 从异常初始化协议响应
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="ex">The ex.</param>
        /// <param name="errorMessage">The error message.</param>
        /// <returns></returns>
        public static T FromException<T>(Exception ex, string errorMessage = null) where T : ProtocolResponse, new()
        {
            var response = new T
            {
                Exception = ex,
                ErrorType = ResponseErrorType.Exception,
                ErrorMessage = errorMessage
            };

            return response;
        }

        /// <summary>
        /// 允许初始化实例特定的数据。
        /// </summary>
        /// <param name="initializationData">The initialization data.</param>
        /// <returns></returns>
        protected virtual Task InitializeAsync(object initializationData = null)
        {
            return Task.CompletedTask;
        }

        /// <summary>
        /// 获取HTTP响应。
        /// </summary>
        /// <value>
        /// The HTTP response.
        /// </value>
        public HttpResponseMessage HttpResponse { get; protected set; }
        
        /// <summary>
        /// 获取原始协议响应（如果存在）。
        /// </summary>
        /// <value>
        /// The raw.
        /// </value>
        public string Raw { get; protected set; }

        /// <summary>
        ///以JSON（如果存在）的形式获取协议响应。
        /// </summary>
        /// <value>
        /// The json.
        /// </value>
        public JObject Json { get; protected set; }

        /// <summary>
        /// 获取异常（如果存在）。
        /// </summary>
        /// <value>
        /// The exception.
        /// </value>
        public Exception Exception { get; protected set; }

        /// <summary>
        /// 获取一个值，该值指示是否发生错误。
        /// </summary>
        /// <value>
        ///   <c>true</c> if an error occurred; otherwise, <c>false</c>.
        /// </value>
        public bool IsError => Error.IsPresent();

        /// <summary>
        ///获取错误的类型。
        /// </summary>
        /// <value>
        /// The type of the error.
        /// </value>
        public ResponseErrorType ErrorType { get; protected set; } = ResponseErrorType.None;

        /// <summary>
        /// 获取或设置一个明确的错误消息。
        /// </summary>
        /// <value>
        /// The type of the error.
        /// </value>
        protected string ErrorMessage { get; set; }

        /// <summary>
        ///获取HTTP状态代码。
        /// </summary>
        /// <value>
        /// The HTTP status code.
        /// </value>
        public HttpStatusCode HttpStatusCode => HttpResponse.StatusCode;

        /// <summary>
        /// 获取HTTP错误原因。
        /// </summary>
        /// <value>
        /// The HTTP error reason.
        /// </value>
        public string HttpErrorReason => HttpResponse.ReasonPhrase;

        /// <summary>
        /// 获取错误。
        /// </summary>
        /// <value>
        /// The error.
        /// </value>
        public string Error
        {
            get
            {
                if (ErrorMessage.IsPresent())
                {
                    return ErrorMessage;
                }
                if (ErrorType == ResponseErrorType.Http)
                {
                    return HttpErrorReason;
                }
                if (ErrorType == ResponseErrorType.Exception)
                {
                    return Exception.Message;
                }

                return TryGet(OidcConstants.TokenResponse.Error);
            }
        }

        /// <summary>
        /// 尝试从JSON响应中获取特定值。
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        public string TryGet(string name) => Json.TryGetString(name);
    }
```
### ResponseErrorType
```
    /// <summary>
    /// 协议端点错误的各种原因
    /// </summary>
    public enum ResponseErrorType
    {
        /// <summary>
        /// none
        /// </summary>
        None,

        /// <summary>
        /// 协议相关-有效的响应，但是某些协议级别的错误。
        /// </summary>
        Protocol,

        /// <summary>
        /// HTTP错误-例如 404。
        /// </summary>
        Http,

        /// <summary>
        /// 发生异常-连接到端点时发生异常，例如 TLS问题。
        /// </summary>
        Exception,

        /// <summary>
        ///策略违规-违反了配置的策略。
        /// </summary>
        PolicyViolation
    }
```
### DeviceAuthorizationRequest
```
    /// <summary>
    /// 要求设备授权
    /// </summary>
    public class DeviceAuthorizationRequest : ProtocolRequest
    {
        /// <summary>
        /// 获取或设置范围（可选）。
        /// </summary>
        /// <value>
        /// The scope.
        /// </value>
        public string Scope { get; set; }
    }
```
### DeviceAuthorizationResponse
```
    /// <summary>
    /// 为OAuth设备授权响应建模
    /// </summary>
    /// <seealso cref="IdentityModel.Client.ProtocolResponse" />
    public class DeviceAuthorizationResponse : ProtocolResponse
    {
        /// <summary>
        ///获取设备验证码。
        /// </summary>
        /// <value>
        /// 设备代码。
        /// </value>
        public string DeviceCode => Json.TryGetString(OidcConstants.DeviceAuthorizationResponse.DeviceCode);

        /// <summary>
        /// 获取最终用户验证码。
        /// </summary>
        /// <value>
        /// The user code.
        /// </value>
        public string UserCode => Json.TryGetString(OidcConstants.DeviceAuthorizationResponse.UserCode);

        /// <summary>
        ///在授权服务器上获取最终用户验证URI。该URI应当简短易记，因为最终用户将被要求手动将其键入用户代理中。
        /// </summary>
        /// <value>
        /// The verification URI.
        /// </value>
        public string VerificationUri => Json.TryGetString(OidcConstants.DeviceAuthorizationResponse.VerificationUri);

        /// <summary>
        /// 获取包含用于非文本传输的“用户代码”（或具有与“用户代码”相同功能的其他信息）的验证URI。
        /// </summary>
        /// <value>
        /// The complete verification URI.
        /// </value>
        public string VerificationUriComplete => Json.TryGetString(OidcConstants.DeviceAuthorizationResponse.VerificationUriComplete);

        /// <summary>
        /// 获取“ device_code”和“ user_code”的生存时间（以秒为单位）。
        /// </summary>
        /// <value>
        /// The expires in.
        /// </value>
        public int? ExpiresIn => Json.TryGetInt(OidcConstants.DeviceAuthorizationResponse.ExpiresIn);

        /// <summary>
        /// 获取客户端在两次轮询令牌端点的请求之间应该等待的最短时间（以秒为单位）。 如果未提供任何值，则客户端必须使用5作为默认值。
        /// </summary>
        /// <value>
        /// The interval.
        /// </value>
        public int Interval => Json.TryGetInt(OidcConstants.DeviceAuthorizationResponse.Interval) ?? 5;

        /// <summary>
        /// 获取错误描述。
        /// </summary>
        /// <value>
        /// The error description.
        /// </value>
        public string ErrorDescription => Json.TryGetString(OidcConstants.TokenResponse.ErrorDescription);
    }
```
### DiscoveryDocumentRequest
```
    /// <summary>
    /// 索取OpenID Connect发现文档
    /// </summary>
    public class DiscoveryDocumentRequest : ProtocolRequest
    {
        /// <summary>
        /// 获取或设置策略。
        /// </summary>
        /// <value>
        /// The policy.
        /// </value>
        public DiscoveryPolicy Policy { get; set; } = new DiscoveryPolicy();
    }
```
### DiscoveryDocumentResponse
```
    /// <summary>
    ///为来自OpenID Connect发现端点的响应建模
    /// </summary>
    public class DiscoveryDocumentResponse : ProtocolResponse
    {
        public DiscoveryPolicy Policy { get; set; }

        protected override Task InitializeAsync(object initializationData = null)
        {
            if (!HttpResponse.IsSuccessStatusCode)
            {
                ErrorMessage = initializationData as string;
                return Task.CompletedTask;
            }

            Policy = initializationData as DiscoveryPolicy ?? new DiscoveryPolicy();

            var validationError = Validate(Policy);

            if (validationError.IsPresent())
            {
                Json = null;

                ErrorType = ResponseErrorType.PolicyViolation;
                ErrorMessage = validationError;
            }

            return Task.CompletedTask;
        }

        /// <summary>
        ///获取或设置JSON Web密钥集。
        /// </summary>
        /// <value>
        /// The key set.
        /// </value>
        public JsonWebKeySet KeySet { get; set; }
        
        // strongly typed
        public string Issuer => TryGetString(OidcConstants.Discovery.Issuer);
        public string AuthorizeEndpoint => TryGetString(OidcConstants.Discovery.AuthorizationEndpoint);
        public string TokenEndpoint => TryGetString(OidcConstants.Discovery.TokenEndpoint);
        public string UserInfoEndpoint => TryGetString(OidcConstants.Discovery.UserInfoEndpoint);
        public string IntrospectionEndpoint => TryGetString(OidcConstants.Discovery.IntrospectionEndpoint);
        public string RevocationEndpoint => TryGetString(OidcConstants.Discovery.RevocationEndpoint);
        public string DeviceAuthorizationEndpoint => TryGetString(OidcConstants.Discovery.DeviceAuthorizationEndpoint);

        public string JwksUri => TryGetString(OidcConstants.Discovery.JwksUri);
        public string EndSessionEndpoint => TryGetString(OidcConstants.Discovery.EndSessionEndpoint);
        public string CheckSessionIframe => TryGetString(OidcConstants.Discovery.CheckSessionIframe);
        public string RegistrationEndpoint => TryGetString(OidcConstants.Discovery.RegistrationEndpoint);
        public bool? FrontChannelLogoutSupported => TryGetBoolean(OidcConstants.Discovery.FrontChannelLogoutSupported);
        public bool? FrontChannelLogoutSessionSupported => TryGetBoolean(OidcConstants.Discovery.FrontChannelLogoutSessionSupported);
        public IEnumerable<string> GrantTypesSupported => TryGetStringArray(OidcConstants.Discovery.GrantTypesSupported);
        public IEnumerable<string> CodeChallengeMethodsSupported => TryGetStringArray(OidcConstants.Discovery.CodeChallengeMethodsSupported);
        public IEnumerable<string> ScopesSupported => TryGetStringArray(OidcConstants.Discovery.ScopesSupported);
        public IEnumerable<string> SubjectTypesSupported => TryGetStringArray(OidcConstants.Discovery.SubjectTypesSupported);
        public IEnumerable<string> ResponseModesSupported => TryGetStringArray(OidcConstants.Discovery.ResponseModesSupported);
        public IEnumerable<string> ResponseTypesSupported => TryGetStringArray(OidcConstants.Discovery.ResponseTypesSupported);
        public IEnumerable<string> ClaimsSupported => TryGetStringArray(OidcConstants.Discovery.ClaimsSupported);
        public IEnumerable<string> TokenEndpointAuthenticationMethodsSupported => TryGetStringArray(OidcConstants.Discovery.TokenEndpointAuthenticationMethodsSupported);

        // generic
        public JToken TryGetValue(string name) => Json.TryGetValue(name);
        public string TryGetString(string name) => Json.TryGetString(name);
        public bool? TryGetBoolean(string name) => Json.TryGetBoolean(name);
        public IEnumerable<string> TryGetStringArray(string name) => Json.TryGetStringArray(name);

        private string Validate(DiscoveryPolicy policy)
        {
            if (policy.ValidateIssuerName)
            {
                IAuthorityValidationStrategy strategy = policy.AuthorityValidationStrategy ?? DiscoveryPolicy.DefaultAuthorityValidationStrategy;

                AuthorityValidationResult issuerValidationResult = strategy.IsIssuerNameValid(Issuer, policy.Authority);

                if (!issuerValidationResult.Success)
                {
                    return issuerValidationResult.ErrorMessage;
                }
            }

            var error = ValidateEndpoints(Json, policy);
            if (error.IsPresent())
            {
                return error;
            }

            return string.Empty;
        }

        /// <summary>
        /// 检查发行人是否与授权匹配。
        /// </summary>
        /// <param name="issuer">The issuer.</param>
        /// <param name="authority">The authority.</param>
        /// <returns></returns>
        public bool ValidateIssuerName(string issuer, string authority)
        {
            return DiscoveryPolicy.DefaultAuthorityValidationStrategy.IsIssuerNameValid(issuer, authority).Success;
        }

        /// <summary>
        /// 检查发行人是否与授权匹配。
        /// </summary>
        /// <param name="issuer">The issuer.</param>
        /// <param name="authority">The authority.</param>
        /// <param name="nameComparison">The comparison mechanism that should be used when performing the match.</param>
        /// <returns></returns>
        public bool ValidateIssuerName(string issuer, string authority, StringComparison nameComparison)
        {
            return new StringComparisonAuthorityValidationStrategy(nameComparison).IsIssuerNameValid(issuer, authority).Success;
        }

        /// <summary>
        /// 检查发行人是否与授权匹配。
        /// </summary>
        /// <param name="issuer">The issuer.</param>
        /// <param name="authority">The authority.</param>
        /// <param name="validationStrategy">The strategy to use.</param>
        /// <returns></returns>
        private bool ValidateIssuerName(string issuer, string authority, IAuthorityValidationStrategy validationStrategy)
        {
            return validationStrategy.IsIssuerNameValid(issuer, authority).Success;
        }




        /// <summary>
        /// 根据安全策略验证endintint和jwks_uri。
        /// </summary>
        /// <param name="json">The json.</param>
        /// <param name="policy">The policy.</param>
        /// <returns></returns>
        public string ValidateEndpoints(JObject json, DiscoveryPolicy policy)
        {
            // allowed hosts
            var allowedHosts = new HashSet<string>(policy.AdditionalEndpointBaseAddresses.Select(e => new Uri(e).Authority))
            {
                new Uri(policy.Authority).Authority
            };

            // allowed authorities (hosts + base address)
            var allowedAuthorities = new HashSet<string>(policy.AdditionalEndpointBaseAddresses)
            {
                policy.Authority
            };

            foreach (var element in json)
            {
                if (element.Key.EndsWith("endpoint", StringComparison.OrdinalIgnoreCase) ||
                    element.Key.Equals(OidcConstants.Discovery.JwksUri, StringComparison.OrdinalIgnoreCase) ||
                    element.Key.Equals(OidcConstants.Discovery.CheckSessionIframe, StringComparison.OrdinalIgnoreCase))
                {
                    var endpoint = element.Value.ToString();

                    var isValidUri = Uri.TryCreate(endpoint, UriKind.Absolute, out Uri uri);
                    if (!isValidUri)
                    {
                        return $"Malformed endpoint: {endpoint}";
                    }

                    if (!DiscoveryEndpoint.IsValidScheme(uri))
                    {
                        return $"Malformed endpoint: {endpoint}";
                    }

                    if (!DiscoveryEndpoint.IsSecureScheme(uri, policy))
                    {
                        return $"Endpoint does not use HTTPS: {endpoint}";
                    }

                    if (policy.ValidateEndpoints)
                    {
                        // if endpoint is on exclude list, don't validate
                        if (policy.EndpointValidationExcludeList.Contains(element.Key))
                        {
                            continue;
                        }

                        bool isAllowed = false;
                        foreach (var host in allowedHosts)
                        {
                            if (string.Equals(host, uri.Authority))
                            {
                                isAllowed = true;
                            }
                        }

                        if (!isAllowed)
                        {
                            return $"Endpoint is on a different host than authority: {endpoint}";
                        }

                        IAuthorityValidationStrategy strategy = policy.AuthorityValidationStrategy ?? DiscoveryPolicy.DefaultAuthorityValidationStrategy;
                        AuthorityValidationResult endpointValidationResult = strategy.IsEndpointValid(endpoint, allowedAuthorities);
                        if (!endpointValidationResult.Success)
                        {
                            return endpointValidationResult.ErrorMessage;
                        }
                    }
                }
            }

            if (policy.RequireKeySet)
            {
                if (string.IsNullOrWhiteSpace(JwksUri))
                {
                    return "Keyset is missing";
                }
            }

            return string.Empty;
        }
    }
```
### DynamicClientRegistrationDocument
```
    /// <summary>
    /// 为OpenID Connect动态客户端注册请求建模
    /// </summary>
    public class DynamicClientRegistrationDocument
    {
        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.RedirectUris, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public ICollection<string> RedirectUris { get; set; } = new HashSet<string>();

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.ResponseTypes, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public ICollection<string> ResponseTypes { get; set; } = new HashSet<string>();

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.GrantTypes, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public ICollection<string> GrantTypes { get; set; } = new HashSet<string>();

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.ApplicationType, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string ApplicationType { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.Contacts, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public ICollection<string> Contacts { get; set; } = new HashSet<string>();

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.ClientName, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string ClientName { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.LogoUri, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string LogoUri { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.ClientUri, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string ClientUri { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.PolicyUri, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string PolicyUri { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.TosUri, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string TosUri { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.JwksUri, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string JwksUri { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.Jwks, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public JsonWebKeySet Jwks { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.SectorIdentifierUri, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string SectorIdentifierUri { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.SubjectType, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string SubjectType { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.IdentityTokenSignedResponseAlgorithm, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string IdentityTokenSignedResponseAlgorithm { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.IdentityTokenEncryptedResponseAlgorithm, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string IdentityTokenEncryptedResponseAlgorithm { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.IdentityTokenEncryptedResponseEncryption, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string IdentityTokenEncryptedResponseEncryption { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.UserinfoSignedResponseAlgorithm, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string UserinfoSignedResponseAlgorithm { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.UserInfoEncryptedResponseAlgorithm, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string UserInfoEncryptedResponseAlgorithm { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.UserinfoEncryptedResponseEncryption, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string UserinfoEncryptedResponseEncryption { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.RequestObjectSigningAlgorithm, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string RequestObjectSigningAlgorithm { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.RequestObjectEncryptionAlgorithm, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string RequestObjectEncryptionAlgorithm { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.RequestObjectEncryptionEncryption, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string RequestObjectEncryptionEncryption { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.TokenEndpointAuthenticationMethod, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string TokenEndpointAuthenticationMethod { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.TokenEndpointAuthenticationSigningAlgorithm, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string TokenEndpointAuthenticationSigningAlgorithm { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.DefaultMaxAge, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public int DefaultMaxAge { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.RequireAuthenticationTime, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public bool RequireAuthenticationTime { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.DefaultAcrValues, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public ICollection<string> DefaultAcrValues { get; set; } = new HashSet<string>();

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.InitiateLoginUris, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public string InitiateLoginUri { get; set; }

        [JsonProperty(PropertyName = OidcConstants.ClientMetadata.RequestUris, DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, Required = Required.Default)]
        public ICollection<string> RequestUris { get; set; } = new HashSet<string>();

        // don't serialize empty arrays
        public bool ShouldSerializeRequestUris()
        {
            return RequestUris.Any();
        }

        public bool ShouldSerializeDefaultAcrValues()
        {
            return DefaultAcrValues.Any();
        }

        public bool ShouldSerializeResponseTypes()
        {
            return ResponseTypes.Any();
        }

        public bool ShouldSerializeGrantTypes()
        {
            return GrantTypes.Any();
        }

        public bool ShouldSerializeContacts()
        {
            return Contacts.Any();
        }
    }
```
### DynamicClientRegistrationRequest
```
    /// <summary>
    /// 要求动态客户注册
    /// </summary>
    /// <seealso cref="ProtocolRequest" />
    public class DynamicClientRegistrationRequest : ProtocolRequest
    {
        /// <summary>
        ///获取或设置令牌。
        /// </summary>
        /// <value>
        /// The token.
        /// </value>
        public string Token { get; set; }

        /// <summary>
        /// 获取或设置注册请求。
        /// </summary>
        /// <value>
        /// The registration request.
        /// </value>
        public DynamicClientRegistrationDocument Document  { get; set; }
    }
```
### DynamicClientRegistrationResponse
```
    /// <summary>
    /// 为OpenID Connect动态客户端注册响应建模
    /// </summary>
    /// <seealso cref="IdentityModel.Client.ProtocolResponse" />
    public class DynamicClientRegistrationResponse : ProtocolResponse
    {
        public string ErrorDescription         => Json.TryGetString("error_description");
        public string ClientId                 => Json.TryGetString(OidcConstants.RegistrationResponse.ClientId);
        public string ClientSecret             => Json.TryGetString(OidcConstants.RegistrationResponse.ClientSecret);
        public string RegistrationAccessToken  => Json.TryGetString(OidcConstants.RegistrationResponse.RegistrationAccessToken);
        public string RegistrationClientUri    => Json.TryGetString(OidcConstants.RegistrationResponse.RegistrationClientUri);
        public int? ClientIdIssuedAt           => Json.TryGetInt(OidcConstants.RegistrationResponse.ClientIdIssuedAt);
        public int? ClientSecretExpiresAt      => Json.TryGetInt(OidcConstants.RegistrationResponse.ClientSecretExpiresAt);
    }
```
### JsonWebKeySetRequest
```
    /// <summary>
    /// 请求JSON Web密钥集文档
    /// </summary>
    public class JsonWebKeySetRequest : ProtocolRequest
    { }
```
### JsonWebKeySetResponse
```
    /// <summary>
    /// 为来自JWK端点的响应建模
    /// </summary>
    /// <seealso cref="IdentityModel.Client.ProtocolResponse" />
    public class JsonWebKeySetResponse : ProtocolResponse
    {
        /// <summary>
        /// Intializes the key set
        /// </summary>
        /// <param name="initializationData"></param>
        /// <returns></returns>
        protected override Task InitializeAsync(object initializationData = null)
        {
            if (!HttpResponse.IsSuccessStatusCode)
            {
                ErrorMessage = initializationData as string;
            }
            else
            {
                KeySet = new JsonWebKeySet(Raw);
            }

            return Task.CompletedTask;
        }

        /// <summary>
        /// The key set
        /// </summary>
        public JsonWebKeySet KeySet { get; set; }
    }
```
### TokenIntrospectionRequest
```
    /// <summary>
    /// 要求OAuth令牌自省
    /// </summary>
    /// <seealso cref="ProtocolRequest" />
    public class TokenIntrospectionRequest : ProtocolRequest
    {
        /// <summary>
        ///获取或设置令牌。
        /// </summary>
        /// <value>
        /// The token.
        /// </value>
        public string Token { get; set; }

        /// <summary>
        /// 获取或设置令牌类型提示。
        /// </summary>
        /// <value>
        /// The token type hint.
        /// </value>
        public string TokenTypeHint { get; set; }
    }
```
### TokenIntrospectionResponse
```
    /// <summary>
    /// 为OAuth 2.0自省响应建模
    /// </summary>
    /// <seealso cref="IdentityModel.Client.ProtocolResponse" />
    public class TokenIntrospectionResponse : ProtocolResponse
    {
        /// <summary>
        /// 允许初始化实例特定的数据。
        /// </summary>
        /// <param name="initializationData">The initialization data.</param>
        /// <returns></returns>
        protected override Task InitializeAsync(object initializationData = null)
        {
            if (!IsError)
            {
                var claims = Json.ToClaims(excludeKeys: "scope").ToList();

                // 由于Identityserver中的错误-我们需要能够处理数组以及以空格分隔的列表格式的作用域列表
                var scope = Json.TryGetValue("scope");

                // scope element exists
                if (scope != null)
                {
                    // it's an array
                    if (scope is JArray scopeArray)
                    {
                        foreach (var item in scopeArray)
                        {
                            claims.Add(new Claim("scope", item.ToString()));
                        }
                    }
                    else
                    {
                        // it's a string
                        var scopeString = scope.ToString();

                        var scopes = scopeString.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var scopeValue in scopes)
                        {
                            claims.Add(new Claim("scope", scopeValue));
                        }
                    }
                }

                Claims = claims;
            }
            else
            {
                Claims = Enumerable.Empty<Claim>();
            }

            return Task.CompletedTask;
        }

        /// <summary>
        /// 获取一个值，该值指示令牌是否处于活动状态。
        /// </summary>
        /// <value>
        ///  <c> true </ c>如果令牌是活动的； 否则为<c> false </ c>。
        /// </value>
        public bool IsActive => Json.TryGetBoolean("active").Value;

        /// <summary>
        ///获取Claim。
        /// </summary>
        /// <value>
        /// The claims.
        /// </value>
        public IEnumerable<Claim> Claims { get; protected set; }
        
    }
```
### TokenRequest
```
    /// <summary>
    /// 索取令牌
    /// </summary>
    /// <seealso cref="ProtocolRequest" />
    public class TokenRequest : ProtocolRequest
    {
        /// <summary>
        ///获取或设置授予的类型。
        /// </summary>
        /// <value>
        /// The type of the grant.
        /// </value>
        public string GrantType { get; set; }   
    }

    /// <summary>
    /// 使用client_credentials请求令牌
    /// </summary>
    /// <seealso cref="TokenRequest" />
    public class ClientCredentialsTokenRequest : TokenRequest
    {
        /// <summary>
        ///获取或设置范围。
        /// </summary>
        /// <value>
        /// The scope.
        /// </value>
        public string Scope { get; set; }
    }

    /// <summary>
    /// 使用urn：ietf：params：oauth：grant-type：device_code请求令牌
    /// </summary>
    /// <seealso cref="TokenRequest" />
    public class DeviceTokenRequest : TokenRequest
    {
        /// <summary>
        /// 获取或设置设备代码。
        /// </summary>
        /// <value>
        /// The scope.
        /// </value>
        public string DeviceCode { get; set; }
    }

    /// <summary>
    /// 使用密码请求令牌
    /// </summary>
    /// <seealso cref="TokenRequest" />
    public class PasswordTokenRequest : TokenRequest
    {
        /// <summary>
        /// 获取或设置用户名。
        /// </summary>
        /// <value>
        /// The name of the user.
        /// </value>
        public string UserName { get; set; }

        /// <summary>
        /// 获取或设置密码。
        /// </summary>
        /// <value>
        /// The password.
        /// </value>
        public string Password { get; set; }

        /// <summary>
        /// 获取或设置范围。
        /// </summary>
        /// <value>
        /// The scope.
        /// </value>
        public string Scope { get; set; }
    }

    /// <summary>
    /// 使用authorization_code请求令牌
    /// </summary>
    /// <seealso cref="TokenRequest" />
    public class AuthorizationCodeTokenRequest : TokenRequest
    {
        /// <summary>
        /// 获取或设置代码。
        /// </summary>
        /// <value>
        /// The code.
        /// </value>
        public string Code { get; set; }

        /// <summary>
        /// 获取或设置重定向URI。
        /// </summary>
        /// <value>
        /// The redirect URI.
        /// </value>
        public string RedirectUri { get; set; }

        /// <summary>
        /// 获取或设置代码验证程序。
        /// </summary>
        /// <value>
        /// The code verifier.
        /// </value>
        public string CodeVerifier { get; set; }
    }

    /// <summary>
    /// 使用refresh_token请求令牌
    /// </summary>
    /// <seealso cref="TokenRequest" />
    public class RefreshTokenRequest : TokenRequest
    {
        /// <summary>
        /// 获取或设置刷新令牌。
        /// </summary>
        /// <value>
        /// The refresh token.
        /// </value>
        public string RefreshToken { get; set; }

        /// <summary>
        ///获取或设置范围。
        /// </summary>
        /// <value>
        /// The scope.
        /// </value>
        public string Scope { get; set; }
    }
```
### TokenResponse
```
    /// <summary>
    /// 为来自OpenID Connect / OAuth 2令牌端点的响应建模
    /// </summary>
    /// <seealso cref="IdentityModel.Client.ProtocolResponse" />
    public class TokenResponse : ProtocolResponse
    {
        /// <summary>
        ///获取访问令牌。
        /// </summary>
        /// <value>
        /// The access token.
        /// </value>
        public string AccessToken => TryGet(OidcConstants.TokenResponse.AccessToken);

        /// <summary>
        ///获取身份令牌。
        /// </summary>
        /// <value>
        /// The identity token.
        /// </value>
        public string IdentityToken => TryGet(OidcConstants.TokenResponse.IdentityToken);

        /// <summary>
        /// 获取令牌的类型。
        /// </summary>
        /// <value>
        /// The type of the token.
        /// </value>
        public string TokenType => TryGet(OidcConstants.TokenResponse.TokenType);

        /// <summary>
        ///获取刷新令牌。
        /// </summary>
        /// <value>
        /// The refresh token.
        /// </value>
        public string RefreshToken => TryGet(OidcConstants.TokenResponse.RefreshToken);

        /// <summary>
        ///获取错误描述。
        /// </summary>
        /// <value>
        /// The error description.
        /// </value>
        public string ErrorDescription => TryGet(OidcConstants.TokenResponse.ErrorDescription);

        /// <summary>
        /// 获取到期时间。
        /// </summary>
        /// <value>
        /// The expires in.
        /// </value>
        public int ExpiresIn
        {
            get
            {
                var value = TryGet(OidcConstants.TokenResponse.ExpiresIn);

                if (value != null)
                {
                    if (int.TryParse(value, out var theValue))
                    {
                        return theValue;
                    }
                }

                return 0;
            }
        }
    }
```
### TokenRevocationRequest
```
    /// <summary>
    ///要求撤销OAuth令牌
    /// </summary>
    /// <seealso cref="IdentityModel.Client.ProtocolRequest" />
    public class TokenRevocationRequest : ProtocolRequest
    {
        /// <summary>
        /// 获取或设置令牌。
        /// </summary>
        /// <value>
        /// The token.
        /// </value>
        public string Token { get; set; }

        /// <summary>
        /// 获取或设置令牌类型提示。
        /// </summary>
        /// <value>
        /// The token type hint.
        /// </value>
        public string TokenTypeHint { get; set; }
    }
```
### TokenRevocationResponse
```
    /// <summary>
    /// 为OAuth 2.0令牌吊销响应建模
    /// </summary>
    /// <seealso cref="IdentityModel.Client.ProtocolResponse" />
    public class TokenRevocationResponse : ProtocolResponse
    { }
```
### UserInfoRequest
```
    /// <summary>
    /// 要求OIDC用户信息
    /// </summary>
    public class UserInfoRequest : ProtocolRequest
    {
        /// <summary>
        ///获取或设置令牌。
        /// </summary>
        /// <value>
        /// The token.
        /// </value>
        public string Token { get; set; }
    }
```