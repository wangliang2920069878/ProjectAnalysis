|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AuthorizationAppBuilderExtensions](#authorizationappbuilderextensions)
* [AuthorizationEndpointConventionBuilderExtensions](#authorizationendpointconventionbuilderextensions)
* [AuthorizationMiddleware](#authorizationmiddleware)
* [AuthorizationPolicyMarkerService](#authorizationpolicymarkerservice)
* [IPolicyEvaluator](#ipolicyevaluator)
* [PolicyAuthorizationResult](#policyauthorizationresult)
* [PolicyEvaluator](#policyevaluator)
* [PolicyServiceCollectionExtensions](#policyservicecollectionextensions)

### AuthorizationAppBuilderExtensions
```
    /// <summary>
    /// 将授权功能添加到HTTP应用程序管道的扩展方法。
    /// </summary>
    public static class AuthorizationAppBuilderExtensions
    {
        /// <summary>
        /// 添加<看到CREF= “AuthorizationMiddleware”/>到指定<看到CREF= “IApplicationBuilder”/>，它使授权功能。
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public static IApplicationBuilder UseAuthorization(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            VerifyServicesRegistered(app);

            return app.UseMiddleware<AuthorizationMiddleware>();
        }

        private static void VerifyServicesRegistered(IApplicationBuilder app)
        {
            // 在调用UseAuthorization之前，请验证是否已调用AddAuthorizationPolicy
            //我们使用AuthorizationPolicyMarkerService确保添加的所有服务。
            if (app.ApplicationServices.GetService(typeof(AuthorizationPolicyMarkerService)) == null)
            {
                throw new InvalidOperationException(Resources.FormatException_UnableToFindServices(
                    nameof(IServiceCollection),
                    nameof(PolicyServiceCollectionExtensions.AddAuthorization),
                    "ConfigureServices(...)"));
            }
        }
    }
```
### AuthorizationEndpointConventionBuilderExtensions
```
    /// <summary>
    /// <see cref =“ IEndpointConventionBuilder” />的授权扩展方法。
    /// </summary>
    public static class AuthorizationEndpointConventionBuilderExtensions
    {
        /// <summary>
        /// 将默认授权策略添加到端点。
        /// </summary>
        /// <param name="builder">端点约定构建器.</param>
        /// <returns>原始约定构建器参数。</returns>
        public static TBuilder RequireAuthorization<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.RequireAuthorization(new AuthorizeAttribute());
        }

        /// <summary>
        /// 将具有指定名称的授权策略添加到端点。
        /// </summary>
        /// <param name="builder">端点约定构建器。</param>
        /// <param name="policyNames">策略名称的集合。 如果为空，将使用默认授权策略。</param>
        /// <returns>原始约定构建器参数.</returns>
        public static TBuilder RequireAuthorization<TBuilder>(this TBuilder builder, params string[] policyNames) where TBuilder : IEndpointConventionBuilder
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (policyNames == null)
            {
                throw new ArgumentNullException(nameof(policyNames));
            }

            return builder.RequireAuthorization(policyNames.Select(n => new AuthorizeAttribute(n)).ToArray());
        }

        /// <summary>
        /// 将具有指定的<see cref =“ IAuthorizeData” />的授权策略添加到端点。
        /// </summary>
        /// <param name="builder">The endpoint convention builder.</param>
        /// <param name="authorizeData">
        /// A collection of <paramref name="authorizeData"/>. If empty, the default authorization policy will be used.
        /// </param>
        /// <returns>The original convention builder parameter.</returns>
        public static TBuilder RequireAuthorization<TBuilder>(this TBuilder builder, params IAuthorizeData[] authorizeData)
            where TBuilder : IEndpointConventionBuilder
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (authorizeData == null)
            {
                throw new ArgumentNullException(nameof(authorizeData));
            }

            if (authorizeData.Length == 0)
            {
                authorizeData = new IAuthorizeData[] { new AuthorizeAttribute(), };
            }

            RequireAuthorizationCore(builder, authorizeData);
            return builder;
        }

        private static void RequireAuthorizationCore<TBuilder>(TBuilder builder, IEnumerable<IAuthorizeData> authorizeData)
            where TBuilder : IEndpointConventionBuilder
        {
            builder.Add(endpointBuilder =>
            {
                foreach (var data in authorizeData)
                {
                    endpointBuilder.Metadata.Add(data);
                }
            });
        }
    }
```
### AuthorizationMiddleware
```
    public class AuthorizationMiddleware
    {
        //属性键由其他系统使用，例如 MVC，检查授权中间件是否已运行
        private const string AuthorizationMiddlewareInvokedKey = "__AuthorizationMiddlewareInvoked";
        private static readonly object AuthorizationMiddlewareInvokedValue = new object();

        private readonly RequestDelegate _next;
        private readonly IAuthorizationPolicyProvider _policyProvider;

        public AuthorizationMiddleware(RequestDelegate next, IAuthorizationPolicyProvider policyProvider)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _policyProvider = policyProvider ?? throw new ArgumentNullException(nameof(policyProvider));
        }

        public async Task Invoke(HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var endpoint = context.GetEndpoint();

            // 标记以指示其他系统，例如 MVC，为此请求运行了授权中间件
            context.Items[AuthorizationMiddlewareInvokedKey] = AuthorizationMiddlewareInvokedValue;

            // 重要说明：对授权逻辑的更改应反映在MVC的AuthorizeFilter中
            var authorizeData = endpoint?.Metadata.GetOrderedMetadata<IAuthorizeData>() ?? Array.Empty<IAuthorizeData>();
            var policy = await AuthorizationPolicy.CombineAsync(_policyProvider, authorizeData);
            if (policy == null)
            {
                await _next(context);
                return;
            }

            //策略评估器具有短暂的生存期，因此它是从请求服务中获取的，而不是注入构造函数中
            var policyEvaluator = context.RequestServices.GetRequiredService<IPolicyEvaluator>();

            var authenticateResult = await policyEvaluator.AuthenticateAsync(policy, context);

            //允许匿名跳过所有授权
            if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() != null)
            {
                await _next(context);
                return;
            }

            // 请注意，如果没有匹配的端点，资源将为null
            var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult, context, resource: endpoint);

            if (authorizeResult.Challenged)
            {
                if (policy.AuthenticationSchemes.Any())
                {
                    foreach (var scheme in policy.AuthenticationSchemes)
                    {
                        await context.ChallengeAsync(scheme);
                    }
                }
                else
                {
                    await context.ChallengeAsync();
                }

                return;
            }
            else if (authorizeResult.Forbidden)
            {
                if (policy.AuthenticationSchemes.Any())
                {
                    foreach (var scheme in policy.AuthenticationSchemes)
                    {
                        await context.ForbidAsync(scheme);
                    }
                }
                else
                {
                    await context.ForbidAsync();
                }

                return;
            }

            await _next(context);
        }
    }
```
### AuthorizationPolicyMarkerService

### IPolicyEvaluator
```
    /// <summary>
    /// 需要为特定需求类型调用的授权处理程序的基类。
    /// </summary>
    public interface IPolicyEvaluator
    {
        /// <summary>
        ///对<see cref =“ AuthorizationPolicy.AuthenticationSchemes” />进行身份验证并设置结果
         /// <see cref =“ ClaimsPrincipal” />到<see cref =“ HttpContext.User” />。 如果未设置任何方案，则为无操作。
        /// </summary>
        /// <param name="policy">The <see cref="AuthorizationPolicy"/>.</param>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns><see cref="AuthenticateResult.Success"/> unless all schemes specified by <see cref="AuthorizationPolicy.AuthenticationSchemes"/> fail to authenticate.  </returns>
        Task<AuthenticateResult> AuthenticateAsync(AuthorizationPolicy policy, HttpContext context);

        /// <summary>
        /// 使用<see cref =“ IAuthorizationService” />尝试授权策略。
        /// </summary>
        /// <param name="policy">The <see cref="AuthorizationPolicy"/>.</param>
        /// <param name="authenticationResult">The result of a call to <see cref="AuthenticateAsync(AuthorizationPolicy, HttpContext)"/>.</param>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="resource">
        /// An optional resource the policy should be checked with.
        /// If a resource is not required for policy evaluation you may pass null as the value.
        /// </param>
        /// <returns>如果授权成功，则返回<see cref =“ PolicyAuthorizationResult.Success” />。
         ///否则，如果<see cref =“ AuthenticateResult.Succeeded” />，则返回<see cref =“ PolicyAuthorizationResult.Forbid” />，否则，否则
         ///返回<see cref =“ PolicyAuthorizationResult.Challenge” /></returns>
        Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object resource);
    }
```
### PolicyAuthorizationResult
```
    public class PolicyAuthorizationResult
    {
        private PolicyAuthorizationResult() { }

        /// <summary>
        /// 如果为true，则表示被叫方应Challenged并重试。
        /// </summary>
        public bool Challenged { get; private set; }

        /// <summary>
        /// 禁止授权。
        /// </summary>
        public bool Forbidden { get; private set; }

        /// <summary>
        /// 授权成功。
        /// </summary>
        public bool Succeeded { get; private set; }

        public static PolicyAuthorizationResult Challenge()
            => new PolicyAuthorizationResult { Challenged = true };

        public static PolicyAuthorizationResult Forbid()
            => new PolicyAuthorizationResult { Forbidden = true };

        public static PolicyAuthorizationResult Success()
            => new PolicyAuthorizationResult { Succeeded = true };

    }
```
### PolicyEvaluator
```
    public class PolicyEvaluator : IPolicyEvaluator
    {
        private readonly IAuthorizationService _authorization;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="authorization">The authorization service.</param>
        public PolicyEvaluator(IAuthorizationService authorization)
        {
            _authorization = authorization;
        }

        /// <summary>
        /// 对<see cref =“ AuthorizationPolicy.AuthenticationSchemes” />进行身份验证并设置结果
         /// <see cref =“ ClaimsPrincipal” />到<see cref =“ HttpContext.User” />。 如果未设置任何方案，则为无操作。
        /// </summary>
        /// <param name="policy">The <see cref="AuthorizationPolicy"/>.</param>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <returns><see cref="AuthenticateResult.Success"/> unless all schemes specified by <see cref="AuthorizationPolicy.AuthenticationSchemes"/> failed to authenticate.  </returns>
        public virtual async Task<AuthenticateResult> AuthenticateAsync(AuthorizationPolicy policy, HttpContext context)
        {
            if (policy.AuthenticationSchemes != null && policy.AuthenticationSchemes.Count > 0)
            {
                ClaimsPrincipal newPrincipal = null;
                foreach (var scheme in policy.AuthenticationSchemes)
                {
                    var result = await context.AuthenticateAsync(scheme);
                    if (result != null && result.Succeeded)
                    {
                        newPrincipal = SecurityHelper.MergeUserPrincipal(newPrincipal, result.Principal);
                    }
                }

                if (newPrincipal != null)
                {
                    context.User = newPrincipal;
                    return AuthenticateResult.Success(new AuthenticationTicket(newPrincipal, string.Join(";", policy.AuthenticationSchemes)));
                }
                else
                {
                    context.User = new ClaimsPrincipal(new ClaimsIdentity());
                    return AuthenticateResult.NoResult();
                }
            }

            return (context.User?.Identity?.IsAuthenticated ?? false) 
                ? AuthenticateResult.Success(new AuthenticationTicket(context.User, "context.User"))
                : AuthenticateResult.NoResult();
        }

        /// <summary>
        /// 使用<see cref =“ IAuthorizationService” />尝试授权策略。
        /// </summary>
        /// <param name="policy">The <see cref="AuthorizationPolicy"/>.</param>
        /// <param name="authenticationResult">The result of a call to <see cref="AuthenticateAsync(AuthorizationPolicy, HttpContext)"/>.</param>
        /// <param name="context">The <see cref="HttpContext"/>.</param>
        /// <param name="resource">
        /// An optional resource the policy should be checked with.
        /// If a resource is not required for policy evaluation you may pass null as the value.
        /// </param>
        /// <returns>如果授权成功，则返回<see cref =“ PolicyAuthorizationResult.Success” />。
         ///否则，如果<see cref =“ AuthenticateResult.Succeeded” />，则返回<see cref =“ PolicyAuthorizationResult.Forbid” />，否则，否则
         ///返回<see cref =“ PolicyAuthorizationResult.Challenge” /></returns>
        public virtual async Task<PolicyAuthorizationResult> AuthorizeAsync(AuthorizationPolicy policy, AuthenticateResult authenticationResult, HttpContext context, object resource)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            var result = await _authorization.AuthorizeAsync(context.User, resource, policy);
            if (result.Succeeded)
            {
                return PolicyAuthorizationResult.Success();
            }

            // If authentication was successful, return forbidden, otherwise challenge
            return (authenticationResult.Succeeded) 
                ? PolicyAuthorizationResult.Forbid() 
                : PolicyAuthorizationResult.Challenge();
        }
    }
```
### PolicyServiceCollectionExtensions
```
    /// <summary>
    /// 在<see cref =“ IServiceCollection” />中设置授权服务的扩展方法。
    /// </summary>
    public static class PolicyServiceCollectionExtensions
    {
        /// <summary>
        ///将授权策略评估程序服务添加到指定的<see cref =“ IServiceCollection” />。
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddAuthorizationPolicyEvaluator(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.TryAddSingleton<AuthorizationPolicyMarkerService>();
            services.TryAdd(ServiceDescriptor.Transient<IPolicyEvaluator, PolicyEvaluator>());
            return services;
        }
        
        /// <summary>
        /// 将授权策略服务添加到指定的<see cref =“ IServiceCollection” />。
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddAuthorization(this IServiceCollection services)
            => services.AddAuthorization(configure: null);

        /// <summary>
        /// 将授权策略服务添加到指定的<see cref =“ IServiceCollection” />。
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <param name="configure">An action delegate to configure the provided <see cref="AuthorizationOptions"/>.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddAuthorization(this IServiceCollection services, Action<AuthorizationOptions> configure)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddAuthorizationCore(configure);
            services.AddAuthorizationPolicyEvaluator();
            return services;
        }
    }
```