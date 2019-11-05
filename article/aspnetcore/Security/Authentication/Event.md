|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AccessDeniedContext](#accessdeniedcontext)
* [BaseContext](#basecontext)
* [HandleRequestContext](#handlerequestcontext)
* [PrincipalContext](#principalcontext)
* [PropertiesContext](#propertiescontext)
* [RedirectContext](#redirectcontext)
* [RemoteAuthenticationContext](#remoteauthenticationcontext)
* [RemoteAuthenticationEvents](#remoteauthenticationevents)
* [RemoteFailureContext](#remotefailurecontext)
* [ResultContext](#resultcontext)
* [TicketReceivedContext](#ticketreceivedcontext)

### AccessDeniedContext
 AccessDeniedContext : HandleRequestContext<RemoteAuthenticationOptions>
    //向处理程序提供程序提供访问被拒绝的失败上下文信息。
```
        /// <summary>
        /// 获取或设置用户代理将重定向到的端点路径。
         ///默认情况下，此属性设置为<see cref =“ RemoteAuthenticationOptions.AccessDeniedPath” />。
        /// </summary>
        public PathString AccessDeniedPath { get; set; }

        /// <summary>
        /// 身份验证会话的其他状态值。
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        /// <summary>
        /// 获取或设置将返回到拒绝访问页面的返回URL。
         ///如果未设置<see cref =“ ReturnUrlParameter” />，则不使用此属性。
        /// </summary>
        public string ReturnUrl { get; set; }

        /// <summary>
        /// 获取或设置将用于传递返回URL的参数名称。
         ///默认情况下，此属性设置为<see cref =“ RemoteAuthenticationOptions.ReturnUrlParameter” />。
        /// </summary>
        public string ReturnUrlParameter { get; set; }
```
### BaseContext
    
```
 /// <summary>
    /////其他上下文类使用的基类。
    /// </summary>
    public abstract class BaseContext<TOptions> where TOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="scheme">The authentication scheme.</param>
        /// <param name="options">The authentication options associated with the scheme.</param>
        protected BaseContext(HttpContext context, AuthenticationScheme scheme, TOptions options)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            if (scheme == null)
            {
                throw new ArgumentNullException(nameof(scheme));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            HttpContext = context;
            Scheme = scheme;
            Options = options;
        }

        /// <summary>
        /// 认证方案。
        /// </summary>
        public AuthenticationScheme Scheme { get; }

        /// <summary>
        /// 获取与方案关联的身份验证选项。
        /// </summary>
        public TOptions Options { get; }

        /// <summary>
        /// 上下文。
        /// </summary>
        public HttpContext HttpContext { get; }

        /// <summary>
        /// The request.
        /// </summary>
        public HttpRequest Request => HttpContext.Request;

        /// <summary>
        /// The response.
        /// </summary>
        public HttpResponse Response => HttpContext.Response;
    }
```
### HandleRequestContext
```
    public class HandleRequestContext<TOptions> : BaseContext<TOptions> where TOptions : AuthenticationSchemeOptions
    {
        protected HandleRequestContext(
            HttpContext context,
            AuthenticationScheme scheme,
            TOptions options)
            : base(context, scheme, options) { }

        /// <summary>
        ///处理程序使用的<see cref =“ HandleRequestResult” />。
        /// </summary>
        public HandleRequestResult Result { get; protected set; }

        /// <summary>
        /// 停止对此请求的所有处理，然后返回到客户端。
         ///调用方负责生成完整的响应。
        /// </summary>
        public void HandleResponse() => Result = HandleRequestResult.Handle();

        /// <summary>
        /// 在当前处理程序中停止处理请求。
        /// </summary>
        public void SkipHandler() => Result = HandleRequestResult.SkipHandler();
    }
```
### PrincipalContext
```
    /// <summary>
    /// 处理ClaimsPrincipal的身份验证事件的基本上下文。
    /// </summary>
    public abstract class PrincipalContext<TOptions> : PropertiesContext<TOptions> where TOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="scheme">The authentication scheme.</param>
        /// <param name="options">The authentication options associated with the scheme.</param>
        /// <param name="properties">The authentication properties.</param>
        protected PrincipalContext(HttpContext context, AuthenticationScheme scheme, TOptions options, AuthenticationProperties properties)
            : base(context, scheme, options, properties) { }

        /// <summary>
        /// 获取包含用户声明的<see cref =“ ClaimsPrincipal” />。
        /// </summary>
        public virtual ClaimsPrincipal Principal { get; set; }
    }
```
### PropertiesContext
```
    /// <summary>
    /// 包含<see cref =“ AuthenticationProperties” />的身份验证事件的基本上下文。
    /// </summary>
    public abstract class PropertiesContext<TOptions> : BaseContext<TOptions> where TOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="scheme">The authentication scheme.</param>
        /// <param name="options">The authentication options associated with the scheme.</param>
        /// <param name="properties">The authentication properties.</param>
        protected PropertiesContext(HttpContext context, AuthenticationScheme scheme, TOptions options, AuthenticationProperties properties)
            : base(context, scheme, options)
        {
            Properties = properties ?? new AuthenticationProperties();
        }

        /// <summary>
        /// 获取或设置<see cref =“ AuthenticationProperties” />。
        /// </summary>
        public virtual AuthenticationProperties Properties { get; protected set; }
    }
```
### RedirectContext
```
   /// <summary>
    /// 为重定向事件传递的上下文。
    /// </summary>
    public class RedirectContext<TOptions> : PropertiesContext<TOptions> where TOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context">The HTTP request context</param>
        /// <param name="scheme">The scheme data</param>
        /// <param name="options">The handler options</param>
        /// <param name="redirectUri">The initial redirect URI</param>
        /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
        public RedirectContext(
            HttpContext context,
            AuthenticationScheme scheme,
            TOptions options,
            AuthenticationProperties properties,
            string redirectUri)
            : base(context, scheme, options, properties)
        {
            Properties = properties;
            RedirectUri = redirectUri;
        }

        /// <summary>
        /// 获取或设置用于重定向操作的URI。
        /// </summary>
        public string RedirectUri { get; set; }
    }
```
### RemoteAuthenticationContext
```
   /// <summary>
    /// 远程身份验证的基本上下文。
    /// </summary>
    public abstract class RemoteAuthenticationContext<TOptions> : HandleRequestContext<TOptions> where TOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="scheme">The authentication scheme.</param>
        /// <param name="options">The authentication options associated with the scheme.</param>
        /// <param name="properties">The authentication properties.</param>
        protected RemoteAuthenticationContext(
            HttpContext context,
            AuthenticationScheme scheme,
            TOptions options,
            AuthenticationProperties properties)
            : base(context, scheme, options)
            => Properties = properties ?? new AuthenticationProperties();

        /// <summary>
        /// 获取包含用户声明的<see cref =“ ClaimsPrincipal” />。
        /// </summary>
        public ClaimsPrincipal Principal { get; set; }

        /// <summary>
        /// 获取或设置<see cref =“ AuthenticationProperties” />。
        /// </summary>
        public virtual AuthenticationProperties Properties { get; set; }

        /// <summary>
        /// 调用成功，使用<see cref =“ Principal” />和<see cref =“ Properties” />创建票证。
        /// </summary>
        public void Success() => Result = HandleRequestResult.Success(new AuthenticationTicket(Principal, Properties, Scheme.Name));

        public void Fail(Exception failure) => Result = HandleRequestResult.Fail(failure);

        public void Fail(string failureMessage) => Result = HandleRequestResult.Fail(failureMessage);
    }
```
### RemoteAuthenticationEvents
```
    public class RemoteAuthenticationEvents
    {
        public Func<AccessDeniedContext, Task> OnAccessDenied { get; set; } = context => Task.CompletedTask;
        public Func<RemoteFailureContext, Task> OnRemoteFailure { get; set; } = context => Task.CompletedTask;

        public Func<TicketReceivedContext, Task> OnTicketReceived { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// 远程服务器返回访问拒绝错误时调用。
        /// </summary>
        public virtual Task AccessDenied(AccessDeniedContext context) => OnAccessDenied(context);

        /// <summary>
        /// 发生远程故障时调用。
        /// </summary>
        public virtual Task RemoteFailure(RemoteFailureContext context) => OnRemoteFailure(context);

        /// <summary>
        /// 在收到远程票证后调用。
        /// </summary>
        public virtual Task TicketReceived(TicketReceivedContext context) => OnTicketReceived(context);
    }
```
### RemoteFailureContext
```
    /// <summary>
    ///向处理程序提供程序提供失败上下文信息。
    /// </summary>
    public class RemoteFailureContext : HandleRequestContext<RemoteAuthenticationOptions>
    {
        public RemoteFailureContext(
            HttpContext context,
            AuthenticationScheme scheme,
            RemoteAuthenticationOptions options,
            Exception failure)
            : base(context, scheme, options)
        {
            Failure = failure;
        }

        /// <summary>
        /// 错误的用户友好错误消息。
        /// </summary>
        public Exception Failure { get; set; }

        /// <summary>
        /// 身份验证会话的其他状态值。
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
```
### ResultContext
```
    /// <summary>
    /// 产生AuthenticateResults的事件的基本上下文。
    /// </summary>
    public abstract class ResultContext<TOptions> : BaseContext<TOptions> where TOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="scheme">The authentication scheme.</param>
        /// <param name="options">The authentication options associated with the scheme.</param>
        protected ResultContext(HttpContext context, AuthenticationScheme scheme, TOptions options)
            : base(context, scheme, options) { }

        /// <summary>
        ///获取或设置包含用户声明的<see cref =“ ClaimsPrincipal” />。
        /// </summary>
        public ClaimsPrincipal Principal { get; set; }

        private AuthenticationProperties _properties;
        /// <summary>
        /// 获取或设置<see cref =“ AuthenticationProperties” />。
        /// </summary>
        public AuthenticationProperties Properties {
            get => _properties ?? (_properties = new AuthenticationProperties());
            set => _properties = value;
        }

        /// <summary>
        /// 获取<see cref =“ AuthenticateResult” />结果。
        /// </summary>
        public AuthenticateResult Result { get; private set; }

        /// <summary>
        /// 调用成功，使用<see cref =“ Principal” />和<see cref =“ Properties” />创建票证。
        /// </summary>
        public void Success() => Result = HandleRequestResult.Success(new AuthenticationTicket(Principal, Properties, Scheme.Name));

        /// <summary>
        /// 表示没有为此认证方案返回任何信息。
        /// </summary>
        public void NoResult() => Result = AuthenticateResult.NoResult();

        /// <summary>
        /// 指示认证期间失败。
        /// </summary>
        /// <param name="failure"></param>
        public void Fail(Exception failure) => Result = AuthenticateResult.Fail(failure);

        /// <summary>
        /// 指示认证期间失败。
        /// </summary>
        /// <param name="failureMessage"></param>
        public void Fail(string failureMessage) => Result = AuthenticateResult.Fail(failureMessage);
    }
```
### TicketReceivedContext
```
    /// <summary>
    /// 向处理程序提供程序提供上下文信息。
    /// </summary>
    public class TicketReceivedContext : RemoteAuthenticationContext<RemoteAuthenticationOptions>
    {
        public TicketReceivedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            RemoteAuthenticationOptions options,
            AuthenticationTicket ticket)
            : base(context, scheme, options, ticket?.Properties)
            => Principal = ticket?.Principal;

        public string ReturnUri { get; set; }
    }
```