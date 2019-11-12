|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [IAuthorityValidationStrategy](#iauthorityvalidationstrategy)
* [AuthorityUrlValidationStrategy](#authorityurlvalidationstrategy)
* [AuthorityValidationResult](#suthorityvalidationresult)
* [BasicAuthenticationHeaderStyle](#basicauthenticationheaderstyle)
* [BasicAuthenticationHeaderValue](#basicauthenticationheadervalue)
* [BasicAuthenticationOAuthHeaderValue](#basicauthenticationoauthheadervalue)
* [ClientCredentialStyle](#clientcredentialstyle)
* [ClientOptions](#clientoptions)
* [DiscoveryCache](#discoverycache)
* [DiscoveryEndpoint](#discoveryendpoint)
* [DiscoveryPolicy](#discoverypolicy)
* [IDiscoveryCache](#idiscoverycache)
* [IntrospectionClient](#introspectionclient)
* [RequestUrl](#requesturl)
* [StringComparisonAuthorityValidationStrategy](#stringcomparisonauthorityvalidationstrategy)
* [TokenClient](#tokenclient)
### IAuthorityValidationStrategy
```
    /// <summary>
    /// 权限验证策略。
    /// </summary>
    public interface IAuthorityValidationStrategy
    {
        /// <summary>
        /// 验证在发现文档中找到的发行者名称。
        /// </summary>
        /// <param name="expectedAuthority">Authority expected.</param>
        /// <param name="issuerName">Authority declared in Discovery Document.</param>
        /// <returns></returns>
        AuthorityValidationResult IsIssuerNameValid(string issuerName, string expectedAuthority);

        /// <summary>
        /// 验证在发现文档中找到的终点。
        /// </summary>
        /// <param name="expectedAuthority">Authority expected.</param>
        /// <param name="endpoint">Endpoint declared in Discovery Document.</param>
        /// <returns></returns>
        AuthorityValidationResult IsEndpointValid(string endpoint, IEnumerable<string> expectedAuthority);
    }
```
### AuthorityUrlValidationStrategy
```
    /// <summary>
<para>基于<see cref =“ Uri” />相等性的<see cref =“ IAuthorityValidationStrategy” />的实现。
     ///尾部的斜杠也将被忽略。</ para>
    /// </summary>
    /// <seealso cref="StringComparisonAuthorityValidationStrategy"/>
    public sealed class AuthorityUrlValidationStrategy : IAuthorityValidationStrategy
    {
        /// <inheritdoc/>判断issuerName与expectedAuthority是url 并且相等
        public AuthorityValidationResult IsIssuerNameValid(string issuerName, string expectedAuthority)
        {
            if (!Uri.TryCreate(expectedAuthority.RemoveTrailingSlash(), UriKind.Absolute, out var expectedAuthorityUrl))
            {
                throw new ArgumentOutOfRangeException("Authority must be a valid URL.", nameof(expectedAuthority));
            }

            if (string.IsNullOrWhiteSpace(issuerName))
            {
                return AuthorityValidationResult.CreateError("Issuer name is missing");
            }

            if (!Uri.TryCreate(issuerName.RemoveTrailingSlash(), UriKind.Absolute, out var issuerUrl))
            {
                return AuthorityValidationResult.CreateError("Issuer name is not a valid URL");
            }

            if (expectedAuthorityUrl.Equals(issuerUrl))
            {
                return AuthorityValidationResult.SuccessResult;
            }

            return AuthorityValidationResult.CreateError("Issuer name does not match authority: " + issuerName);
        }

        /// <inheritdoc/>//判断endpoint和集合allowedAuthorities中的都是url,并且endpoint以allowedAuthorities中的url开头
        public AuthorityValidationResult IsEndpointValid(string endpoint, IEnumerable<string> allowedAuthorities)
        {
            if (string.IsNullOrEmpty(endpoint))
            {
                return AuthorityValidationResult.CreateError("endpoint is empty");
            }

            if (!Uri.TryCreate(endpoint.RemoveTrailingSlash(), UriKind.Absolute, out var endpointUrl))
            {
                return AuthorityValidationResult.CreateError("Endpoint is not a valid URL");
            }

            foreach (string authority in allowedAuthorities)
            {
                if (!Uri.TryCreate(authority.RemoveTrailingSlash(), UriKind.Absolute, out var authorityUrl))
                {
                    throw new ArgumentOutOfRangeException("Authority must be a URL.", nameof(allowedAuthorities));
                }

                string expectedString = authorityUrl.ToString();
                string testString = endpointUrl.ToString();

                if (testString.StartsWith(expectedString, StringComparison.Ordinal))
                {
                    return AuthorityValidationResult.SuccessResult;
                }

            }

            return AuthorityValidationResult.CreateError($"Endpoint belongs to different authority: {endpoint}");
        }
    }
```
### AuthorityValidationResult
```
    public struct AuthorityValidationResult
    {
        public static readonly AuthorityValidationResult SuccessResult = new AuthorityValidationResult(true, null);

        public string ErrorMessage { get; }

        public bool Success { get; }

        private AuthorityValidationResult(bool success, string message)
        {
            if (!success && string.IsNullOrEmpty(message))
                throw new ArgumentException("A message must be provided if success=false.", nameof(message));

            ErrorMessage = message;
            Success = success;
        }

        public static AuthorityValidationResult CreateError(string message)
        {
            return new AuthorityValidationResult(false, message);
        }

        public override string ToString()
        {
            return Success ? "success" : ErrorMessage;
        }
    }
```
### BasicAuthenticationHeaderStyle
```
    /// <summary>
    /// 用于指定基本身份验证标头的编码风格的枚举
    /// </summary>
    public enum BasicAuthenticationHeaderStyle
    {
        /// <summary>
        /// 推荐的。 使用OAuth 2.0规范（https://tools.ietf.org/html/rfc6749#section-2.3.1）中所述的编码。 Base64（urlformencode（client_id）+“：” + urlformencode（client_secret））
        /// </summary>
        Rfc6749,
        /// <summary>
        /// 使用原始基本身份验证规范（https://tools.ietf.org/html/rfc2617#section-2-一些不符合OAuth 2.0的授权服务器使用的编码）中所述的编码。 Base64（client_id +“：” + client_secret）。
        /// </summary>
        Rfc2617
    }
```
### BasicAuthenticationHeaderValue
```
    /// <summary>
    ///HTTP基本身份验证授权标头
    /// </summary>
    /// <seealso cref="System.Net.Http.Headers.AuthenticationHeaderValue" />
    public class BasicAuthenticationHeaderValue : AuthenticationHeaderValue
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BasicAuthenticationHeaderValue"/> class.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password.</param>
        public BasicAuthenticationHeaderValue(string userName, string password)
            : base("Basic", EncodeCredential(userName, password))
        { }

        /// <summary>
        /// 对证书进行编码。
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">userName</exception>
        public static string EncodeCredential(string userName, string password)
        {
            if (string.IsNullOrWhiteSpace(userName)) throw new ArgumentNullException(nameof(userName));
            if (password == null) password = "";

            Encoding encoding = Encoding.UTF8;
            string credential = String.Format("{0}:{1}", userName, password);

            return Convert.ToBase64String(encoding.GetBytes(credential));
        }
    }
```
### BasicAuthenticationOAuthHeaderValue
```
    /// <summary>
    ///RFC6749客户端身份验证的HTTP基本身份验证授权标头
    /// </summary>
    /// <seealso cref="System.Net.Http.Headers.AuthenticationHeaderValue" />
    public class BasicAuthenticationOAuthHeaderValue : AuthenticationHeaderValue
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BasicAuthenticationOAuthHeaderValue"/> class.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password.</param>
        public BasicAuthenticationOAuthHeaderValue(string userName, string password)
            : base("Basic", EncodeCredential(userName, password))
        { }

        /// <summary>
        /// 对证书进行编码。
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">userName</exception>
        public static string EncodeCredential(string userName, string password)
        {
            if (string.IsNullOrWhiteSpace(userName)) throw new ArgumentNullException(nameof(userName));
            if (password == null) password = "";

            Encoding encoding = Encoding.UTF8;
            string credential = $"{UrlEncode(userName)}:{UrlEncode(password)}";

            return Convert.ToBase64String(encoding.GetBytes(credential));
        }

        private static string UrlEncode(string value)
        {
            if (String.IsNullOrEmpty(value))
            {
                return String.Empty;
            }
            
            return Uri.EscapeDataString(value).Replace("%20", "+");
        }
    }
```
### ClientCredentialStyle
```
    /// <summary>
    /// 指定客户端如何传输客户端ID和密码
    /// </summary>
    public enum ClientCredentialStyle
    {
        /// <summary>
        /// HTTP基本认证
        /// </summary>
        AuthorizationHeader,

        /// <summary>
        ///正文中的值
        /// </summary>
        PostBody
    };
```
### ClientOptions
```
    /// <summary>
    ///TokenClient的选项
    /// </summary>
    public class TokenClientOptions : ClientOptions
    { }

    /// <summary>
    ///IntrospectionClient的选项
    /// </summary>
    public class IntrospectionClientOptions : ClientOptions
    { }

    /// <summary>
    /// 基本类协议客户端选项
    /// </summary>
    public abstract class ClientOptions
    {
        /// <summary>
        /// 获取或设置地址。
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
        /// 获取或设置客户端凭据样式。
        /// </summary>
        /// <value>
        /// The client credential style.
        /// </value>
        public ClientCredentialStyle ClientCredentialStyle { get; set; } = ClientCredentialStyle.PostBody;

        /// <summary>
        /// 获取或设置基本身份验证标头样式。
        /// </summary>
        /// <value>
        /// The basic authentication header style.
        /// </value>
        public BasicAuthenticationHeaderStyle AuthorizationHeaderStyle { get; set; } = BasicAuthenticationHeaderStyle.Rfc6749;

        /// <summary>
        /// 获取或设置其他请求参数（不得与本地设置的参数冲突）
        /// </summary>
        /// <value>
        /// The parameters.
        /// </value>
        public IDictionary<string, string> Parameters { get; set; } = new Dictionary<string, string>();
    }
```
### DiscoveryCache
```
    /// <summary>
    /// 用于缓存发现文档的助手。
    /// </summary>
    public class DiscoveryCache : IDiscoveryCache
    {
        private DateTime _nextReload = DateTime.MinValue;
        private AsyncLazy<DiscoveryDocumentResponse> _lazyResponse;

        private readonly DiscoveryPolicy _policy;
        private readonly Func<HttpMessageInvoker> _getHttpClient;
        private readonly string _authority;

        /// <summary>
        /// Initialize instance of DiscoveryCache with passed authority.
        /// </summary>
        /// <param name="authority">Base address or discovery document endpoint.</param>
        /// <param name="policy">The policy.</param>
        public DiscoveryCache(string authority, DiscoveryPolicy policy = null)
        {
            _authority = authority;
            _policy = policy ?? new DiscoveryPolicy();
            _getHttpClient = () => new HttpClient();
        }

        /// <summary>
        /// Initialize instance of DiscoveryCache with passed authority.
        /// </summary>
        /// <param name="authority">基地址或发现文档端点。</param>
        /// <param name="httpClientFunc">HTTP客户端功能。</param>
        /// <param name="policy">The policy.</param>
        public DiscoveryCache(string authority, Func<HttpMessageInvoker> httpClientFunc, DiscoveryPolicy policy = null)
        {
            _authority = authority;
            _policy = policy ?? new DiscoveryPolicy();
            _getHttpClient = httpClientFunc ?? throw new ArgumentNullException(nameof(httpClientFunc));
        }

        /// <summary>
        /// 刷新发现文档的频率。 默认为24小时。
        /// </summary>
        public TimeSpan CacheDuration { get; set; } = TimeSpan.FromHours(24);

        /// <summary>
        /// 从缓存或发现端点获取DiscoveryResponse。
        /// </summary>
        /// <returns></returns>
        public Task<DiscoveryDocumentResponse> GetAsync()
        {
            if (_nextReload <= DateTime.UtcNow)
            {
                Refresh();
            }

            return _lazyResponse.Value;
        }

        /// <summary>
        /// 将发现文档标记为过时，并在下一个获取DiscoveryResponse的请求上触发对发现端点的请求。
        /// </summary>
        public void Refresh()
        {
            _lazyResponse = new AsyncLazy<DiscoveryDocumentResponse>(GetResponseAsync);
        }

        private async Task<DiscoveryDocumentResponse> GetResponseAsync()
        {
            var result = await _getHttpClient().GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
            {
                Address = _authority,
                Policy = _policy
            });

            if (result.IsError)
            {
                Refresh();
                _nextReload = DateTime.MinValue;
            }
            else
            {
                _nextReload = DateTime.UtcNow.Add(CacheDuration);
            }

            return result;
        }
    }
```
### DiscoveryEndpoint
```
    /// <summary>
    /// 表示发现端点的URL-解析以分隔URL和授权
    /// </summary>
    public class DiscoveryEndpoint
    {
        /// <summary>
        /// 解析URL，并将其转换为授权和发现端点URL。
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns></returns>
        /// <exception cref="System.InvalidOperationException">
        /// Malformed URL
        /// </exception>
        public static DiscoveryEndpoint ParseUrl(string input)
        {
            var success = Uri.TryCreate(input, UriKind.Absolute, out var uri);
            if (success == false)
            {
                throw new InvalidOperationException("Malformed URL");
            }

            if (!DiscoveryEndpoint.IsValidScheme(uri))
            {
                throw new InvalidOperationException("Malformed URL");
            }

            var url = input.RemoveTrailingSlash();

            if (url.EndsWith(OidcConstants.Discovery.DiscoveryEndpoint, StringComparison.OrdinalIgnoreCase))
            {
                return new DiscoveryEndpoint(url.Substring(0, url.Length - OidcConstants.Discovery.DiscoveryEndpoint.Length - 1), url);
            }
            else
            {
                return new DiscoveryEndpoint(url, url.EnsureTrailingSlash() + OidcConstants.Discovery.DiscoveryEndpoint);
            }
        }

        /// <summary>
        ///确定URL使用http还是https。
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <returns>
        ///   <c>true</c> if [is valid scheme] [the specified URL]; otherwise, <c>false</c>.
        /// </returns>
        public static bool IsValidScheme(Uri url)
        {
            if (string.Equals(url.Scheme, "http", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(url.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// 根据策略确定是否使用安全方案。
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <param name="policy">The policy.</param>
        /// <returns>
        ///   <c>true</c> if [is secure scheme] [the specified URL]; otherwise, <c>false</c>.
        /// </returns>
        public static bool IsSecureScheme(Uri url, DiscoveryPolicy policy)
        {
            if (policy.RequireHttps == true)
            {
                if (policy.AllowHttpOnLoopback == true)
                {
                    var hostName = url.DnsSafeHost;

                    foreach (var address in policy.LoopbackAddresses)
                    {
                        if (string.Equals(hostName, address, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }

                return string.Equals(url.Scheme, "https", StringComparison.OrdinalIgnoreCase);
            }

            return true;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DiscoveryEndpoint"/> class.
        /// </summary>
        /// <param name="authority">The authority.</param>
        /// <param name="url">The discovery endpoint URL.</param>
        public DiscoveryEndpoint(string authority, string url)
        {
            Authority = authority;
            Url = url;
        }
        /// <summary>
        /// 获取或设置权限。
        /// </summary>
        /// <value>
        /// The authority.
        /// </value>
        public string Authority { get; }

        /// <summary>
        /// 获取或设置发现端点。
        /// </summary>
        /// <value>
        /// The discovery endpoint.
        /// </value>
        public string Url { get; }
    }
```
### DiscoveryPolicy
```
    /// <summary>
    /// 检索发现文档的安全策略
    /// </summary>
    public class DiscoveryPolicy
    {
        internal static readonly IAuthorityValidationStrategy DefaultAuthorityValidationStrategy = new StringComparisonAuthorityValidationStrategy();

        /// <summary>
        /// 获取或设置将基于其进行策略检查的授权机构
        /// </summary>
        public string Authority { get; set; }

        /// <summary>
        /// 用于根据预期权限验证发行者名称和端点的策略。
         ///默认为<see cref =“ AuthorityUrlValidationStrategy” />。
        /// </summary>
        public IAuthorityValidationStrategy AuthorityValidationStrategy { get; set; } = DefaultAuthorityValidationStrategy;

        /// <summary>
        /// 指定是否在所有端点上强制实施HTTPS。 默认为true。
        /// </summary>
        public bool RequireHttps { get; set; } = true;

        /// <summary>
        /// 指定是否在回送地址上允许使用HTTP。 默认为true。
        /// </summary>
        public bool AllowHttpOnLoopback { get; set; } = true;

        /// <summary>
        /// 指定有效的回送地址，默认为localhost和127.0.0.1
        /// </summary>
        public ICollection<string> LoopbackAddresses = new HashSet<string> { "localhost", "127.0.0.1" };

        /// <summary>
        /// 指定是否检查发行者名称是否与授权机构相同。 默认为true。
        /// </summary>
        public bool ValidateIssuerName { get; set; } = true;

        /// <summary>
        /// 指定是否检查所有端点都属于权限。 默认为true。
        /// </summary>
        public bool ValidateEndpoints { get; set; } = true;

        /// <summary>
        /// 指定应从验证中排除的端点列表
        /// </summary>
        public ICollection<string> EndpointValidationExcludeList { get; set; } = new HashSet<string>();

        /// <summary>
        /// 指定端点应允许的其他基本地址的列表
        /// </summary>
        public ICollection<string> AdditionalEndpointBaseAddresses { get; set; } = new HashSet<string>();

        /// <summary>
        /// 指定是否需要密钥集。 默认为true。
        /// </summary>
        public bool RequireKeySet { get; set; } = true;
    }
```
# IDiscoveryCache
```
    /// <summary>
    /// 发现缓存的接口
    /// </summary>
    public interface IDiscoveryCache
    {
        /// <summary>
        /// 获取或设置缓存的持续时间。
        /// </summary>
        /// <value>
        /// The duration of the cache.
        /// </value>
        TimeSpan CacheDuration { get; set; }

        /// <summary>
        /// 检索发现文件
        /// </summary>
        /// <returns></returns>
        Task<DiscoveryDocumentResponse> GetAsync();

        /// <summary>
        /// 在下一次获取时强制刷新。
        /// </summary>
        void Refresh();
    }
```
### IntrospectionClient
```
    /// <summary>
    /// OAuth 2自省端点的客户端库
    /// </summary>
    public class IntrospectionClient
    {
        private readonly Func<HttpMessageInvoker> _client;
        private readonly IntrospectionClientOptions _options;

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="client"></param>
        /// <param name="options"></param>
        public IntrospectionClient(HttpMessageInvoker client, IntrospectionClientOptions options)
            : this(() => client, options)
        { }

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="client func"></param>
        /// <param name="options"></param>
        public IntrospectionClient(Func<HttpMessageInvoker> client, IntrospectionClientOptions options)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// 从选项设置请求参数。
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="parameters">The parameters.</param>
        internal void ApplyRequestParameters(TokenIntrospectionRequest request, IDictionary<string, string> parameters)
        {
            request.Address = _options.Address;
            request.ClientId = _options.ClientId;
            request.ClientSecret = _options.ClientSecret;
            request.ClientAssertion = _options.ClientAssertion;
            request.ClientCredentialStyle = _options.ClientCredentialStyle;
            request.AuthorizationHeaderStyle = _options.AuthorizationHeaderStyle;
            request.Parameters = _options.Parameters;

            if (parameters != null)
            {
                foreach (var parameter in parameters)
                {
                    request.Parameters.Add(parameter);
                }
            }
        }

        /// <summary>
        /// 自省令牌
        /// </summary>
        /// <param name="token"></param>
        /// <param name="tokenTypeHint"></param>
        /// <param name="parameters"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public Task<TokenIntrospectionResponse> Introspect(string token, string tokenTypeHint = null, IDictionary<string, string> parameters = null, CancellationToken cancellationToken = default)
        {
            var request = new TokenIntrospectionRequest
            {
                Token = token,
                TokenTypeHint = tokenTypeHint
            };
            ApplyRequestParameters(request, parameters);

            return _client().IntrospectTokenAsync(request, cancellationToken);
        }
    }
```
### RequestUrl
```
    /// <summary>
    /// 用于创建请求URL的帮助器类
    /// </summary>
    public class RequestUrl
    {
        private readonly string _baseUrl;

        /// <summary>
        /// Initializes a new instance of the <see cref="RequestUrl"/> class.
        /// </summary>
        /// <param name="baseUrl">The authorize endpoint.</param>
        public RequestUrl(string baseUrl)
        {
            _baseUrl = baseUrl;
        }

        /// <summary>
        /// 根据键/值输入对创建URL。
        /// </summary>
        /// <param name="values">The values (either as a Dictionary of string/string or as a type with properties).</param>
        /// <returns></returns>
        public string Create(object values)
        {
            var dictionary = ValuesHelper.ObjectToDictionary(values);
            if (dictionary == null || !dictionary.Any())
            {
                return _baseUrl;
            }

            return QueryHelpers.AddQueryString(_baseUrl, dictionary);
        }
    }
```
### StringComparisonAuthorityValidationStrategy
```
    /// <summary>
    /// 基于<see cref =“ StringComparison” />的<see cref =“ IAuthorityValidationStrategy” />的实现。
    /// </summary>
    /// <seealso cref="AuthorityUrlValidationStrategy"/>
    public sealed class StringComparisonAuthorityValidationStrategy : IAuthorityValidationStrategy
    {
        private readonly StringComparison _stringComparison;

        /// <summary>
        /// Constructor with <see cref="StringComparison"/> argument.
        /// </summary>
        /// <param name="stringComparison"></param>
        public StringComparisonAuthorityValidationStrategy(StringComparison stringComparison = StringComparison.Ordinal)
        {
            _stringComparison = stringComparison;
        }

        /// <summary>
        /// 发行者和授权者之间的字符串比较（忽略斜线）。
        /// </summary>
        /// <param name="issuerName"></param>
        /// <param name="expectedAuthority"></param>
        /// <returns></returns>
        public AuthorityValidationResult IsIssuerNameValid(string issuerName, string expectedAuthority)
        {
            if (string.IsNullOrWhiteSpace(issuerName)) return AuthorityValidationResult.CreateError("Issuer name is missing");

            if (string.Equals(issuerName.RemoveTrailingSlash(), expectedAuthority.RemoveTrailingSlash(), _stringComparison))
                return AuthorityValidationResult.SuccessResult;

            return AuthorityValidationResult.CreateError("Issuer name does not match authority: " + issuerName);
        }

        /// <summary>
        /// 端点和允许的授权机构之间的比较字符串“开始于”。
        /// </summary>
        /// <param name="endpoint"></param>
        /// <param name="allowedAuthorities"></param>
        /// <returns></returns>
        public AuthorityValidationResult IsEndpointValid(string endpoint, IEnumerable<string> allowedAuthorities)
        {
            if (string.IsNullOrEmpty(endpoint))
                return AuthorityValidationResult.CreateError("endpoint is empty");

            foreach (string authority in allowedAuthorities)
            {
                if (endpoint.StartsWith(authority, _stringComparison))
                    return AuthorityValidationResult.SuccessResult;
            }

            return AuthorityValidationResult.CreateError($"Endpoint belongs to different authority: {endpoint}");
        }
    }
```
### TokenClient
```
    /// <summary>
    /// OpenID Connect / OAuth 2令牌端点的客户端库
    /// </summary>
    public class TokenClient
    {
        private readonly Func<HttpMessageInvoker> _client;
        private readonly TokenClientOptions _options;

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenClient"/> class.
        /// </summary>
        /// <param name="client">The client.</param>
        /// <param name="options">The options.</param>
        /// <exception cref="ArgumentNullException">client</exception>
        public TokenClient(HttpMessageInvoker client, TokenClientOptions options)
            : this(() => client, options)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenClient"/> class.
        /// </summary>
        /// <param name="client">The client func.</param>
        /// <param name="options">The options.</param>
        /// <exception cref="ArgumentNullException">client</exception>
        public TokenClient(Func<HttpMessageInvoker> client, TokenClientOptions options)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// 从选项设置请求参数。
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="parameters">The parameters.</param>
        internal void ApplyRequestParameters(TokenRequest request, IDictionary<string, string> parameters)
        {
            request.Address = _options.Address;
            request.ClientId = _options.ClientId;
            request.ClientSecret = _options.ClientSecret;
            request.ClientAssertion = _options.ClientAssertion;
            request.ClientCredentialStyle = _options.ClientCredentialStyle;
            request.AuthorizationHeaderStyle = _options.AuthorizationHeaderStyle;
            request.Parameters = _options.Parameters;

            if (parameters != null)
            {
                foreach (var parameter in parameters)
                {
                    request.Parameters.Add(parameter);
                }
            }
        }

        /// <summary>
        ///使用client_credentials授予类型发送令牌请求。
        /// </summary>
        /// <param name="scope">The scope (space separated string).</param>
        /// <param name="parameters">Extra parameters.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public Task<TokenResponse> RequestClientCredentialsTokenAsync(string scope = null, IDictionary<string, string> parameters = null, CancellationToken cancellationToken = default)
        {
            var request = new ClientCredentialsTokenRequest
            {
                Scope = scope
            };
            ApplyRequestParameters(request, parameters);

            return _client().RequestClientCredentialsTokenAsync(request, cancellationToken);
        }

        /// <summary>
        ///使用urn：ietf：params：oauth：grant-type：device_code授予类型发送令牌请求。
        /// </summary>
        /// <param name="deviceCode">设备代码.</param>
        /// <param name="parameters">Extra parameters.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public Task<TokenResponse> RequestDeviceTokenAsync(string deviceCode, IDictionary<string, string> parameters = null, CancellationToken cancellationToken = default)
        {
            var request = new DeviceTokenRequest
            {
                DeviceCode = deviceCode
            };
            ApplyRequestParameters(request, parameters);

            return _client().RequestDeviceTokenAsync(request, cancellationToken);
        }

        /// <summary>
        /// 使用密码授予类型发送令牌请求。
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password.</param>
        /// <param name="scope">范围（用空格分隔的字符串）.</param>
        /// <param name="parameters">Extra parameters.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public Task<TokenResponse> RequestPasswordTokenAsync(string userName, string password = null, string scope = null, IDictionary<string, string> parameters = null, CancellationToken cancellationToken = default)
        {
            var request = new PasswordTokenRequest
            {
                UserName = userName,
                Password = password,
                Scope = scope
            };
            ApplyRequestParameters(request, parameters);

            return _client().RequestPasswordTokenAsync(request, cancellationToken);
        }

        /// <summary>
        /// 使用authorization_code授权类型发送令牌请求。
        /// </summary>
        /// <param name="code">The code.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="codeVerifier">代码验证器.</param>
        /// <param name="parameters">The parameters.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public Task<TokenResponse> RequestAuthorizationCodeTokenAsync(string code, string redirectUri, string codeVerifier = null, IDictionary<string, string> parameters = null, CancellationToken cancellationToken = default)
        {
            var request = new AuthorizationCodeTokenRequest
            {
                Code = code,
                RedirectUri = redirectUri,
                CodeVerifier = codeVerifier
            };
            ApplyRequestParameters(request, parameters);

            return _client().RequestAuthorizationCodeTokenAsync(request, cancellationToken);
        }

        /// <summary>
        /// 使用refresh_token授权类型发送令牌请求。
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="scope">The scope (space separated string).</param>
        /// <param name="parameters">Extra parameters.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public Task<TokenResponse> RequestRefreshTokenAsync(string refreshToken, string scope = null, IDictionary<string, string> parameters = null, CancellationToken cancellationToken = default)
        {
            var request = new RefreshTokenRequest
            {
                RefreshToken = refreshToken,
                Scope = scope
            };
            ApplyRequestParameters(request, parameters);

            return _client().RequestRefreshTokenAsync(request, cancellationToken);
        }

        /// <summary>
        /// 发送令牌请求。
        /// </summary>
        /// <param name="grantType">Type of the grant.</param>
        /// <param name="parameters">Extra parameters.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns></returns>
        public Task<TokenResponse> RequestTokenAsync(string grantType, IDictionary<string, string> parameters = null, CancellationToken cancellationToken = default)
        {
            var request = new TokenRequest
            {
                GrantType = grantType
            };
            ApplyRequestParameters(request, parameters);

            return _client().RequestTokenAsync(request, cancellationToken);
        }
    }
```
