|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [AllowAnonymousAttribute](#allowanonymousattribute)
* [AssertionRequirement](#assertionrequirement)
* [AuthorizationFailure](#authorizationfailure)
* [AuthorizationHandler](#authorizationhandler)
* [AuthorizationHandlerContext](#authorizationhandlercontext)
* [AuthorizationOptions](#authorizationoptions)
* [AuthorizationPolicy](#authorizationpolicy)
* [AuthorizationPolicyBuilder](#authorizationpolicybuilder)
* [AuthorizationResult](#authorizationresult)
* [AuthorizationServiceCollectionExtensions](#authorizationservicecollectionextensions)
* [AuthorizationServiceExtensions](#authorizationserviceextensions)
* [AuthorizeAttribute](#authorizeattribute)
* [ClaimsAuthorizationRequirement](#claimsauthorizationrequirement)
* [DefaultAuthorizationEvaluator](#defaultauthorizationevaluator)
* [DefaultAuthorizationHandlerContextFactory](#defaultauthorizationhandlercontextfactory)
* [DefaultAuthorizationHandlerProvider](#defaultauthorizationhandlerprovider)
* [DefaultAuthorizationPolicyProvider](#defaultauthorizationpolicyprovider)
* [DefaultAuthorizationService](#defaultauthorizationservice)
* [DenyAnonymousAuthorizationRequirement](#denyanonymousauthorizationrequirement)
* [NameAuthorizationRequirement](#nameauthorizationrequirement)
* [OperationAuthorizationRequirement](#operationauthorizationrequirement)
* [PassThroughAuthorizationHandler](#passthroughauthorizationhandler)
* [RolesAuthorizationRequirement](#rolesauthorizationrequirement)
* [IAuthorizationEvaluator](#IAuthorizationEvaluator)
* [IAuthorizationHandler](#IAuthorizationHandler)
* [IAuthorizationHandlerContextFactory](#IAuthorizationHandlerContextFactory)
* [IAuthorizationHandlerProvider](#IAuthorizationHandlerProvider)
* [IAuthorizationPolicyProvider](#IAuthorizationPolicyProvider)
* [IAuthorizationRequirement](#IAuthorizationRequirement)
* [IAuthorizationService](#IAuthorizationService)
### AllowAnonymousAttribute
```
    /// <summary>
    /// 指定此属性应用于的类或方法不需要授权。
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public class AllowAnonymousAttribute : Attribute, IAllowAnonymous
    {
    }
```
### AssertionRequirement
```
    /// <summary>
    /// 实现<see cref =“ IAuthorizationHandler” />和<see cref =“ IAuthorizationRequirement” />
     ///接受用户指定的断言。
    /// </summary>
    public class AssertionRequirement : IAuthorizationHandler, IAuthorizationRequirement
    {
        /// <summary>
        /// 用来处理此要求的函数。
        /// </summary>
        public Func<AuthorizationHandlerContext, Task<bool>> Handler { get; }

        /// <summary>
        /// 创建<see cref =“ AssertionRequirement” />的新实例。
        /// </summary>
        /// <param name="handler">Function that is called to handle this requirement.</param>
        public AssertionRequirement(Func<AuthorizationHandlerContext, bool> handler)
        {
            if (handler == null)
            {
                throw new ArgumentNullException(nameof(handler));
            }

            Handler = context => Task.FromResult(handler(context));
        }

        /// <summary>
        /// 创建<see cref =“ AssertionRequirement” />的新实例。
        /// </summary>
        /// <param name="handler">Function that is called to handle this requirement.</param>
        public AssertionRequirement(Func<AuthorizationHandlerContext, Task<bool>> handler)
        {
            if (handler == null)
            {
                throw new ArgumentNullException(nameof(handler));
            }

            Handler = handler;
        }

        /// <summary>
        /// 调用<see cref =“ AssertionRequirement.Handler” />以查看授权是否allowed.
        /// </summary>
        /// <param name="context">The authorization information.</param>
        public async Task HandleAsync(AuthorizationHandlerContext context)
        {
            if (await Handler(context))
            {
                context.Succeed(this);
            }
        }
    }
```
### AuthorizationFailure
```
    /// <summary>
    /// 封装<see cref =“ IAuthorizationService.AuthorizeAsync（ClaimsPrincipal，object，IEnumerable {IAuthorizationRequirement}）” />的失败结果。
    /// </summary>
    public class AuthorizationFailure
    {
        private AuthorizationFailure() { }

        /// <summary>
        /// 失败是由于<see cref =“ AuthorizationHandlerContext.Fail” />被调用。
        /// </summary>
        public bool FailCalled { get; private set; }

        /// <summary>
        /// 失败是由于无法通过<see cref =“ AuthorizationHandlerContext.Succeed（IAuthorizationRequirement）” />满足这些要求。
        /// </summary>
        public IEnumerable<IAuthorizationRequirement> FailedRequirements { get; private set; }

        /// <summary>
        ///由于调用<see cref =“ AuthorizationHandlerContext.Fail” />而导致失败。
        /// </summary>
        /// <returns>The failure.</returns>
        public static AuthorizationFailure ExplicitFail()
            => new AuthorizationFailure
            {
                FailCalled = true,
                FailedRequirements = new IAuthorizationRequirement[0]
            };

        /// <summary>
        /// 由于未通过<see cref =“ AuthorizationHandlerContext.Succeed（IAuthorizationRequirement）” />满足某些要求而返回失败。
        /// </summary>
        /// <param name="failed">The requirements that were not met.</param>
        /// <returns>The failure.</returns>
        public static AuthorizationFailure Failed(IEnumerable<IAuthorizationRequirement> failed)
            => new AuthorizationFailure { FailedRequirements = failed };

    }
```
### AuthorizationHandler
```
    /// <summary>
    /// 需要为特定需求类型调用的授权处理程序的基类。
    /// </summary>
    /// <typeparam name="TRequirement">需要处理的类型.</typeparam>
    public abstract class AuthorizationHandler<TRequirement> : IAuthorizationHandler
            where TRequirement : IAuthorizationRequirement
    {
        /// <summary>
        /// 决定是否允许授权。
        /// </summary>
        /// <param name="context">The authorization context.</param>
        public virtual async Task HandleAsync(AuthorizationHandlerContext context)
        {
            foreach (var req in context.Requirements.OfType<TRequirement>())
            {
                await HandleRequirementAsync(context, req);
            }
        }

        /// <summary>
        /// 根据特定要求来决定是否允许授权。
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        protected abstract Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement);
    }

    /// <summary>
    /// 需要针对特定要求而需要调用的授权处理程序的基类
     ///资源类型。
    /// </summary>
    /// <typeparam name="TRequirement">需要评估的类型。</typeparam>
    /// <typeparam name="TResource">要评估的资源类型。</typeparam>
    public abstract class AuthorizationHandler<TRequirement, TResource> : IAuthorizationHandler
        where TRequirement : IAuthorizationRequirement
    {
        /// <summary>
        /// 决定是否允许授权。
        /// </summary>
        /// <param name="context">授权上下文.</param>
        public virtual async Task HandleAsync(AuthorizationHandlerContext context)
        {
            if (context.Resource is TResource)
            {
                foreach (var req in context.Requirements.OfType<TRequirement>())
                {
                    await HandleRequirementAsync(context, req, (TResource)context.Resource);
                }
            }
        }

        /// <summary>
        /// 根据特定要求和资源来决定是否允许授权。
        /// </summary>
        /// <param name="context">授权上下文.</param>
        /// <param name="requirement">评估要求。</param>
        /// <param name="resource">评估资源.</param>
        protected abstract Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement, TResource resource);
    }
```
### AuthorizationHandlerContext
```
    /// <summary>
    ///包含由<see cref =“ IAuthorizationHandler” />使用的授权信息。
    /// </summary>
    public class AuthorizationHandlerContext
    {
        private HashSet<IAuthorizationRequirement> _pendingRequirements;
        private bool _failCalled;
        private bool _succeedCalled;

        /// <summary>
        ///创建<see cref =“ AuthorizationHandlerContext” />的新实例。
        /// </summary>
        /// <param name="requirements">当前授权操作的所有<see cref =“ IAuthorizationRequirement” />的集合。</param>
        /// <param name="user">代表当前用户的<see cref =“ ClaimsPrincipal” />。</param>
        /// <param name="resource">用来评估<paramref name =“ requirements” />的可选资源。</param>
        public AuthorizationHandlerContext(
            IEnumerable<IAuthorizationRequirement> requirements,
            ClaimsPrincipal user,
            object resource)
        {
            if (requirements == null)
            {
                throw new ArgumentNullException(nameof(requirements));
            }

            Requirements = requirements;
            User = user;
            Resource = resource;
            _pendingRequirements = new HashSet<IAuthorizationRequirement>(requirements);
        }

        /// <summary>
        /// 当前授权操作的所有<see cref =“ IAuthorizationRequirement” />的集合。
        /// </summary>
        public virtual IEnumerable<IAuthorizationRequirement> Requirements { get; }

        /// <summary>
        /// <see cref =“ ClaimsPrincipal” />代表当前用户。
        /// </summary>
        public virtual ClaimsPrincipal User { get; }

        /// <summary>
        /// 用来评估<see cref =“ AuthorizationHandlerContext.Requirements” />的可选资源。
        /// </summary>
        public virtual object Resource { get; }

        /// <summary>
        ///获取尚未标记为成功的需求。   
        /// </summary>
        public virtual IEnumerable<IAuthorizationRequirement> PendingRequirements { get { return _pendingRequirements; } }

        /// <summary>
        /// 指示当前授权处理是否失败的标志。
        /// </summary>
        public virtual bool HasFailed { get { return _failCalled; } }

        /// <summary>
        /// 指示当前授权处理是否成功的标志。
        /// </summary>
        public virtual bool HasSucceeded
        {
            get
            {
                return !_failCalled && _succeedCalled && !PendingRequirements.Any();
            }
        }

        /// <summary>
        /// 调用以表示<see cref =“ AuthorizationHandlerContext.HasSucceeded” />
         ///即使满足所有要求，也永远不要返回true。
        /// </summary>
        public virtual void Fail()
        {
            _failCalled = true;
        }

        /// <summary>
        ///调用以将指定的<paramref name =“ requirement” />标记为
         ///成功评估。
        /// </summary>
        /// <param name="requirement">评估成功的需求。</param>
        public virtual void Succeed(IAuthorizationRequirement requirement)
        {
            _succeedCalled = true;
            _pendingRequirements.Remove(requirement);
        }
    }
```
### AuthorizationOptions
```
    /// <summary>
    /// 提供<see cref =“ IAuthorizationService” />和<see cref =“ IAuthorizationPolicyProvider” />使用的编程配置。
    /// </summary>
    public class AuthorizationOptions
    {
        private IDictionary<string, AuthorizationPolicy> PolicyMap { get; } = new Dictionary<string, AuthorizationPolicy>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// 确定是否在失败后调用身份验证处理程序。
         ///默认为true。
        /// </summary>
        public bool InvokeHandlersAfterFailure { get; set; } = true;

        /// <summary>
        /// 获取或设置默认授权策略。 默认情况下要求经过身份验证的用户。
        /// </summary>
        /// <remarks>
        /// 评估<see cref =“ IAuthorizeData” />时使用的默认策略，未指定任何策略名称。
        /// </remarks>
        public AuthorizationPolicy DefaultPolicy { get; set; } = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();

        /// <summary>
        ///获取或设置<see cref =“ AuthorizationPolicy.CombineAsync（IAuthorizationPolicyProvider，IEnumerable {IAuthorizeData}）” />使用的后备授权策略
         ///当未提供IAuthorizeData时。 结果，AuthorizationMiddleware使用了回退策略
         ///如果没有资源的<see cref =“ IAuthorizeData” />实例。 如果资源具有任何<see cref =“ IAuthorizeData” />
         ///然后对它们进行评估，而不是回退策略。 默认情况下，后备策略为null，通常不会
         ///除非管道中有AuthorizationMiddleware，否则会生效。 它不以任何方式使用
         ///默认<see cref =“ IAuthorizationService” />。
        /// </summary>
        public AuthorizationPolicy FallbackPolicy { get; set; }

        /// <summary>
        /// 使用提供的名称添加授权策略。
        /// </summary>
        /// <param name="name">策略的名称。</param>
        /// <param name="policy">授权策略。</param>
        public void AddPolicy(string name, AuthorizationPolicy policy)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            PolicyMap[name] = policy;
        }

        /// <summary>
        /// 添加从具有提供的名称的委托构建的策略。
        /// </summary>
        /// <param name="name">政策名称.</param>
        /// <param name="configurePolicy">将用于构建策略的委托。</param>
        public void AddPolicy(string name, Action<AuthorizationPolicyBuilder> configurePolicy)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (configurePolicy == null)
            {
                throw new ArgumentNullException(nameof(configurePolicy));
            }

            var policyBuilder = new AuthorizationPolicyBuilder();
            configurePolicy(policyBuilder);
            PolicyMap[name] = policyBuilder.Build();
        }

        /// <summary>
        /// 返回指定名称的策略；如果使用该名称的策略不存在，则返回null。
        /// </summary>
        /// <param name="name">要返回的策略的名称。</param>
        /// <returns>指定名称的策略；如果不存在具有该名称的策略，则为null.</returns>
        public AuthorizationPolicy GetPolicy(string name)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            return PolicyMap.ContainsKey(name) ? PolicyMap[name] : null;
        }
    }
```
### AuthorizationPolicy
```
    /// <summary>
    /// 代表授权要求和方案的集合，或
     ///对它们进行评估的方案，所有方案都必须成功
     ///授权成功。
    /// </summary>
    public class AuthorizationPolicy
    {
        /// <summary>
        /// Creates a new instance of <see cref="AuthorizationPolicy"/>.
        /// </summary>
        /// <param name="requirements">
        /// <see cref =“ IAuthorizationRequirement” />的列表，该列表必须成功
         ///此政策成功。
        /// </param>
        /// <param name="authenticationSchemes">
        /// 评估<paramref name =“ requirements” />认证方案。
        /// </param>
        public AuthorizationPolicy(IEnumerable<IAuthorizationRequirement> requirements, IEnumerable<string> authenticationSchemes)
        {
            if (requirements == null)
            {
                throw new ArgumentNullException(nameof(requirements));
            }

            if (authenticationSchemes == null)
            {
                throw new ArgumentNullException(nameof(authenticationSchemes));
            }

            if (requirements.Count() == 0)
            {
                throw new InvalidOperationException(Resources.Exception_AuthorizationPolicyEmpty);
            }
            Requirements = new List<IAuthorizationRequirement>(requirements).AsReadOnly();
            AuthenticationSchemes = new List<string>(authenticationSchemes).AsReadOnly();
        }

        /// <summary>
        /// 获取<see cref =“ IAuthorizationRequirement” />的只读列表，该列表必须成功
         ///此政策成功。
        /// </summary>
        public IReadOnlyList<IAuthorizationRequirement> Requirements { get; }

        /// <summary>
        /// 获取身份验证方案的只读列表，请参见<see cref =“ AuthorizationPolicy.Requirements” />
         ///进行评估。
        /// </summary>
        public IReadOnlyList<string> AuthenticationSchemes { get; }

        /// <summary>
        /// 将指定的<see cref =“ AuthorizationPolicy” />组合到一个策略中。
        /// </summary>
        /// <param name="policies">要组合的授权策略。</param>
        /// <returns>
        /// 新的<see cref =“ AuthorizationPolicy” />代表了以下内容的组合：
         ///指定了<paramref name =“ policies” />。
        /// </returns>
        public static AuthorizationPolicy Combine(params AuthorizationPolicy[] policies)
        {
            if (policies == null)
            {
                throw new ArgumentNullException(nameof(policies));
            }

            return Combine((IEnumerable<AuthorizationPolicy>)policies);
        }

        /// <summary>
        /// 将指定的<see cref =“ AuthorizationPolicy” />组合到一个策略中。
        /// </summary>
        /// <param name="policies">The authorization policies to combine.</param>
        /// <returns>
        /// A new <see cref="AuthorizationPolicy"/> which represents the combination of the
        /// specified <paramref name="policies"/>.
        /// </returns>
        public static AuthorizationPolicy Combine(IEnumerable<AuthorizationPolicy> policies)
        {
            if (policies == null)
            {
                throw new ArgumentNullException(nameof(policies));
            }

            var builder = new AuthorizationPolicyBuilder();
            foreach (var policy in policies)
            {
                builder.Combine(policy);
            }
            return builder.Build();
        }

        /// <summary>
        ///合并指定的提供的<see cref =“ AuthorizationPolicy” />
         /// <paramref name =“ policyProvider” />。
        /// </summary>
        /// <param name="policyProvider">一个<see cref =“ IAuthorizationPolicyProvider” />，它提供了组合策略.</param>
        /// <param name="authorizeData">授权数据集合，用于将授权应用于资源。</param>
        /// <returns>
        /// 新的<see cref =“ AuthorizationPolicy” />代表了以下内容的组合：
         ///由指定的<paramref name =“ policyProvider” />提供的授权策略。
        /// </returns>
        public static async Task<AuthorizationPolicy> CombineAsync(IAuthorizationPolicyProvider policyProvider, IEnumerable<IAuthorizeData> authorizeData)
        {
            if (policyProvider == null)
            {
                throw new ArgumentNullException(nameof(policyProvider));
            }

            if (authorizeData == null)
            {
                throw new ArgumentNullException(nameof(authorizeData));
            }

            // 如果已知数据为空，请避免分配枚举数
            var skipEnumeratingData = false;
            if (authorizeData is IList<IAuthorizeData> dataList)
            {
                skipEnumeratingData = dataList.Count == 0;
            }

            AuthorizationPolicyBuilder policyBuilder = null;
            if (!skipEnumeratingData)
            {
                foreach (var authorizeDatum in authorizeData)
                {
                    if (policyBuilder == null)
                    {
                        policyBuilder = new AuthorizationPolicyBuilder();
                    }

                    var useDefaultPolicy = true;
                    if (!string.IsNullOrWhiteSpace(authorizeDatum.Policy))
                    {
                        var policy = await policyProvider.GetPolicyAsync(authorizeDatum.Policy);
                        if (policy == null)
                        {
                            throw new InvalidOperationException(Resources.FormatException_AuthorizationPolicyNotFound(authorizeDatum.Policy));
                        }
                        policyBuilder.Combine(policy);
                        useDefaultPolicy = false;
                    }

                    var rolesSplit = authorizeDatum.Roles?.Split(',');
                    if (rolesSplit != null && rolesSplit.Any())
                    {
                        var trimmedRolesSplit = rolesSplit.Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => r.Trim());
                        policyBuilder.RequireRole(trimmedRolesSplit);
                        useDefaultPolicy = false;
                    }

                    var authTypesSplit = authorizeDatum.AuthenticationSchemes?.Split(',');
                    if (authTypesSplit != null && authTypesSplit.Any())
                    {
                        foreach (var authType in authTypesSplit)
                        {
                            if (!string.IsNullOrWhiteSpace(authType))
                            {
                                policyBuilder.AuthenticationSchemes.Add(authType.Trim());
                            }
                        }
                    }

                    if (useDefaultPolicy)
                    {
                        policyBuilder.Combine(await policyProvider.GetDefaultPolicyAsync());
                    }
                }
            }

            // 如果我们目前没有政策，请使用后备政策（如果有）
            if (policyBuilder == null)
            {
                var fallbackPolicy = await policyProvider.GetFallbackPolicyAsync();
                if (fallbackPolicy != null)
                {
                    return fallbackPolicy;
                }
            }

            return policyBuilder?.Build();
        }
    }
```
### AuthorizationPolicyBuilder
```
    /// <summary>
    /// 用于在应用程序启动期间构建策略。
    /// </summary>
    public class AuthorizationPolicyBuilder
    {
        /// <summary>
        /// Creates a new instance of <see cref="AuthorizationPolicyBuilder"/>
        /// </summary>
        /// <param name="authenticationSchemes">An array of authentication schemes the policy should be evaluated against.</param>
        public AuthorizationPolicyBuilder(params string[] authenticationSchemes)
        {
            AddAuthenticationSchemes(authenticationSchemes);
        }

        /// <summary>
        /// Creates a new instance of <see cref="AuthorizationPolicyBuilder"/>.
        /// </summary>
        /// <param name="policy">The <see cref="AuthorizationPolicy"/> to build.</param>
        public AuthorizationPolicyBuilder(AuthorizationPolicy policy)
        {
            Combine(policy);
        }

        /// <summary>
        /// 获取或设置<see cref =“ IAuthorizationRequirement” />的列表，该列表必须成功
         ///此政策成功。
        /// </summary>
        public IList<IAuthorizationRequirement> Requirements { get; set; } = new List<IAuthorizationRequirement>();

        /// <summary>
        ///获取或设置列表身份验证方案，请参见<see cref =“ AuthorizationPolicyBuilder.Requirements” />
         ///进行评估。
        /// </summary>
        public IList<string> AuthenticationSchemes { get; set; } = new List<string>();

        /// <summary>
        /// 将指定的身份验证<paramref name =“ schemes” />添加到
         /// <请参阅cref =“ AuthorizationPolicyBuilder.AuthenticationSchemes” />此实例。
        /// </summary>
        /// <param name="schemes">The schemes to add.</param>
        /// <returns>操作完成后对此实例的引用.</returns>
        public AuthorizationPolicyBuilder AddAuthenticationSchemes(params string[] schemes)
        {
            foreach (var authType in schemes)
            {
                AuthenticationSchemes.Add(authType);
            }
            return this;
        }

        /// <summary>
        /// 将指定的<paramref name =“ requirements” />添加到
         /// <请参阅cref =“ AuthorizationPolicyBuilder.Requirements” />此实例。
        /// </summary>
        /// <param name="requirements">授权要求添加.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public AuthorizationPolicyBuilder AddRequirements(params IAuthorizationRequirement[] requirements)
        {
            foreach (var req in requirements)
            {
                Requirements.Add(req);
            }
            return this;
        }

        /// <summary>
        /// 将指定的<paramref name =“ policy” />合并到当前实例中。
        /// </summary>
        /// <param name="policy">The <see cref="AuthorizationPolicy"/> to combine.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public AuthorizationPolicyBuilder Combine(AuthorizationPolicy policy)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            AddAuthenticationSchemes(policy.AuthenticationSchemes.ToArray());
            AddRequirements(policy.Requirements.ToArray());
            return this;
        }

        /// <summary>
        ///添加<see cref =“ ClaimsAuthorizationRequirement” />
         ///到当前实例。
        /// </summary>
        /// <param name="claimType">The claim type required.</param>
        /// <param name="allowedValues">Values the claim must process one or more of for evaluation to succeed.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public AuthorizationPolicyBuilder RequireClaim(string claimType, params string[] allowedValues)
        {
            if (claimType == null)
            {
                throw new ArgumentNullException(nameof(claimType));
            }

            return RequireClaim(claimType, (IEnumerable<string>)allowedValues);
        }

        /// <summary>
        /// 添加<see cref =“ ClaimsAuthorizationRequirement” />
         ///到当前实例。
        /// </summary>
        /// <param name="claimType">The claim type required.</param>
        /// <param name="allowedValues">Values the claim must process one or more of for evaluation to succeed.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public AuthorizationPolicyBuilder RequireClaim(string claimType, IEnumerable<string> allowedValues)
        {
            if (claimType == null)
            {
                throw new ArgumentNullException(nameof(claimType));
            }

            Requirements.Add(new ClaimsAuthorizationRequirement(claimType, allowedValues));
            return this;
        }

        /// <summary>
        /// 添加<see cref =“ ClaimsAuthorizationRequirement” />
         ///到当前实例。
        /// </summary>
        /// <param name="claimType">The claim type required, which no restrictions on claim value.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public AuthorizationPolicyBuilder RequireClaim(string claimType)
        {
            if (claimType == null)
            {
                throw new ArgumentNullException(nameof(claimType));
            }

            Requirements.Add(new ClaimsAuthorizationRequirement(claimType, allowedValues: null));
            return this;
        }

        /// <summary>
        /// 添加<see cref =“ RolesAuthorizationRequirement” />
         ///到当前实例。
        /// </summary>
        /// <param name="roles">The allowed roles.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public AuthorizationPolicyBuilder RequireRole(params string[] roles)
        {
            if (roles == null)
            {
                throw new ArgumentNullException(nameof(roles));
            }

            return RequireRole((IEnumerable<string>)roles);
        }

        /// <summary>
        ///添加<see cref =“ RolesAuthorizationRequirement” />
         ///到当前实例。
        /// </summary>
        /// <param name="roles">The allowed roles.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public AuthorizationPolicyBuilder RequireRole(IEnumerable<string> roles)
        {
            if (roles == null)
            {
                throw new ArgumentNullException(nameof(roles));
            }

            Requirements.Add(new RolesAuthorizationRequirement(roles));
            return this;
        }

        /// <summary>
        /// 添加<see cref =“ NameAuthorizationRequirement” />
         ///到当前实例。
        /// </summary>
        /// <param name="userName">The user name the current user must possess.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public AuthorizationPolicyBuilder RequireUserName(string userName)
        {
            if (userName == null)
            {
                throw new ArgumentNullException(nameof(userName));
            }

            Requirements.Add(new NameAuthorizationRequirement(userName));
            return this;
        }

        /// <summary>
        /// 将<see cref =“ DenyAnonymousAuthorizationRequirement” />添加到当前实例。
        /// </summary>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public AuthorizationPolicyBuilder RequireAuthenticatedUser()
        {
            Requirements.Add(new DenyAnonymousAuthorizationRequirement());
            return this;
        }

        /// <summary>
        /// 向当前实例添加<see cref =“ AssertionRequirement” />。
        /// </summary>
        /// <param name="handler">The handler to evaluate during authorization.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public AuthorizationPolicyBuilder RequireAssertion(Func<AuthorizationHandlerContext, bool> handler)
        {
            if (handler == null)
            {
                throw new ArgumentNullException(nameof(handler));
            }

            Requirements.Add(new AssertionRequirement(handler));
            return this;
        }

        /// <summary>
        /// Adds an <see cref="AssertionRequirement"/> to the current instance.
        /// </summary>
        /// <param name="handler">The handler to evaluate during authorization.</param>
        /// <returns>A reference to this instance after the operation has completed.</returns>
        public AuthorizationPolicyBuilder RequireAssertion(Func<AuthorizationHandlerContext, Task<bool>> handler)
        {
            if (handler == null)
            {
                throw new ArgumentNullException(nameof(handler));
            }

            Requirements.Add(new AssertionRequirement(handler));
            return this;
        }

        /// <summary>
        /// Builds a new <see cref="AuthorizationPolicy"/> from the requirements 
        /// in this instance.
        /// </summary>
        /// <returns>
        /// A new <see cref="AuthorizationPolicy"/> built from the requirements in this instance.
        /// </returns>
        public AuthorizationPolicy Build()
        {
            return new AuthorizationPolicy(Requirements, AuthenticationSchemes.Distinct());
        }
    }
```
### AuthorizationResult
```
    /// <summary>
    /// 封装<see cref =“ IAuthorizationService.AuthorizeAsync（ClaimsPrincipal，object，IEnumerable {IAuthorizationRequirement}）” />的结果。
    /// </summary>
    public class AuthorizationResult
    {
        private AuthorizationResult() { }

        /// <summary>
        /// 如果授权成功，则为true。
        /// </summary>
        public bool Succeeded { get; private set; }

        /// <summary>
        /// 包含有关授权失败原因的信息。
        /// </summary>
        public AuthorizationFailure Failure { get; private set; }

        /// <summary>
        ///返回成功的结果。
        /// </summary>
        /// <returns>A successful result.</returns>
        public static AuthorizationResult Success() => new AuthorizationResult { Succeeded = true };

        public static AuthorizationResult Failed(AuthorizationFailure failure) => new AuthorizationResult { Failure = failure };

        public static AuthorizationResult Failed() => new AuthorizationResult { Failure = AuthorizationFailure.ExplicitFail() };

    }
```
### AuthorizationServiceCollectionExtensions
```
    /// <summary>
    ///在<see cref =“ IServiceCollection” />中设置授权服务的扩展方法。
    /// </summary>
    public static class AuthorizationServiceCollectionExtensions
    {
        /// <summary>
        /// 将授权服务添加到指定的<see cref =“ IServiceCollection” />。
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddAuthorizationCore(this IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }
            
            services.TryAdd(ServiceDescriptor.Transient<IAuthorizationService, DefaultAuthorizationService>());
            services.TryAdd(ServiceDescriptor.Transient<IAuthorizationPolicyProvider, DefaultAuthorizationPolicyProvider>());
            services.TryAdd(ServiceDescriptor.Transient<IAuthorizationHandlerProvider, DefaultAuthorizationHandlerProvider>());
            services.TryAdd(ServiceDescriptor.Transient<IAuthorizationEvaluator, DefaultAuthorizationEvaluator>());
            services.TryAdd(ServiceDescriptor.Transient<IAuthorizationHandlerContextFactory, DefaultAuthorizationHandlerContextFactory>());
            services.TryAddEnumerable(ServiceDescriptor.Transient<IAuthorizationHandler, PassThroughAuthorizationHandler>());
            return services;
        }

        /// <summary>
        /// 将授权服务添加到指定的<see cref =“ IServiceCollection” />。
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection" /> to add services to.</param>
        /// <param name="configure">An action delegate to configure the provided <see cref="AuthorizationOptions"/>.</param>
        /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddAuthorizationCore(this IServiceCollection services, Action<AuthorizationOptions> configure)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configure != null)
            {
                services.Configure(configure);
            }

            return services.AddAuthorizationCore();
        }
    }
```
### AuthorizationServiceExtensions
```
    /// <summary>
    /// <请参阅cref =“ IAuthorizationService” />的扩展方法。
    /// </summary>
    public static class AuthorizationServiceExtensions
    {
        /// <summary>
        /// 检查用户是否满足指定资源的特定要求
        /// </summary>
        /// <param name="service">The <see cref="IAuthorizationService"/> 提供授权.</param>
        /// <param name="user">用于评估策略的用户。</param>
        /// <param name="resource">用于评估策略的资源。</param>
        /// <param name="requirement">评估策略所依据的要求。</param>
        /// <returns>
        ///一个标志，指示需求评估是成功还是失败。
         ///当用户满足策略时，此值为<value> true </ value>，否则为<value> false </ value>。
        /// </returns>
        public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, object resource, IAuthorizationRequirement requirement)
        {
            if (service == null)
            {
                throw new ArgumentNullException(nameof(service));
            }

            if (requirement == null)
            {
                throw new ArgumentNullException(nameof(requirement));
            }

            return service.AuthorizeAsync(user, resource, new IAuthorizationRequirement[] { requirement });
        }

        /// <summary>
        /// Checks if a user meets a specific authorization policy against the specified resource.
        /// </summary>
        /// <param name="service">The <see cref="IAuthorizationService"/> providing authorization.</param>
        /// <param name="user">The user to evaluate the policy against.</param>
        /// <param name="resource">The resource to evaluate the policy against.</param>
        /// <param name="policy">评估政策.</param>
        /// <returns>
        /// A flag indicating whether policy evaluation has succeeded or failed.
        /// This value is <value>true</value> when the user fulfills the policy, otherwise <value>false</value>.
        /// </returns>
        public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, object resource, AuthorizationPolicy policy)
        {
            if (service == null)
            {
                throw new ArgumentNullException(nameof(service));
            }

            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            return service.AuthorizeAsync(user, resource, policy.Requirements);
        }

        /// <summary>
        /// Checks if a user meets a specific authorization policy against the specified resource.
        /// </summary>
        /// <param name="service">The <see cref="IAuthorizationService"/> providing authorization.</param>
        /// <param name="user">The user to evaluate the policy against.</param>
        /// <param name="policy">The policy to evaluate.</param>
        /// <returns>
        /// A flag indicating whether policy evaluation has succeeded or failed.
        /// This value is <value>true</value> when the user fulfills the policy, otherwise <value>false</value>.
        /// </returns>
        public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, AuthorizationPolicy policy)
        {
            if (service == null)
            {
                throw new ArgumentNullException(nameof(service));
            }

            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            return service.AuthorizeAsync(user, resource: null, policy: policy);
        }

        /// <summary>
        /// Checks if a user meets a specific authorization policy against the specified resource.
        /// </summary>
        /// <param name="service">The <see cref="IAuthorizationService"/> providing authorization.</param>
        /// <param name="user">The user to evaluate the policy against.</param>
        /// <param name="policyName">The name of the policy to evaluate.</param>
        /// <returns>
        /// A flag indicating whether policy evaluation has succeeded or failed.
        /// This value is <value>true</value> when the user fulfills the policy, otherwise <value>false</value>.
        /// </returns>
        public static Task<AuthorizationResult> AuthorizeAsync(this IAuthorizationService service, ClaimsPrincipal user, string policyName)
        {
            if (service == null)
            {
                throw new ArgumentNullException(nameof(service));
            }

            if (policyName == null)
            {
                throw new ArgumentNullException(nameof(policyName));
            }

            return service.AuthorizeAsync(user, resource: null, policyName: policyName);
        }
    }
```
### AuthorizeAttribute
```
    /// <summary>
    ///指定应用此属性的类或方法需要指定的授权。
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class AuthorizeAttribute : Attribute, IAuthorizeData
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizeAttribute"/> class. 
        /// </summary>
        public AuthorizeAttribute() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthorizeAttribute"/> class with the specified policy. 
        /// </summary>
        /// <param name="policy">The name of the policy to require for authorization.</param>
        public AuthorizeAttribute(string policy)
        {
            Policy = policy;
        }

        /// <summary>
        /// 获取或设置确定对资源的访问的策略名称。
        /// </summary>
        public string Policy { get; set; }

        /// <summary>
        /// 获取或设置以逗号分隔的允许访问资源的角色列表。
        /// </summary>
        public string Roles { get; set; }

        /// <summary>
        ///获取或设置以逗号分隔的方案列表，从中可以构造用户信息。
        /// </summary>
        public string AuthenticationSchemes { get; set; }
    }
```
### ClaimsAuthorizationRequirement
```
    /// <summary>
    /// 实现<see cref =“ IAuthorizationHandler” />和<see cref =“ IAuthorizationRequirement” />
     ///，它至少需要一个指定的声明类型的实例，并且，如果指定了允许的值，
     ///声明值必须是任何允许的值。
    /// </summary>
    public class ClaimsAuthorizationRequirement : AuthorizationHandler<ClaimsAuthorizationRequirement>, IAuthorizationRequirement
    {
        /// <summary>
        /// Creates a new instance of <see cref="ClaimsAuthorizationRequirement"/>.
        /// </summary>
        /// <param name="claimType">The claim type that must be present.</param>
        /// <param name="allowedValues">The optional list of claim values, which, if present, 
        /// the claim must match.</param>
        public ClaimsAuthorizationRequirement(string claimType, IEnumerable<string> allowedValues)
        {
            if (claimType == null)
            {
                throw new ArgumentNullException(nameof(claimType));
            }

            ClaimType = claimType;
            AllowedValues = allowedValues;
        }

        /// <summary>
        /// 获取必须存在的声明类型。
        /// </summary>
        public string ClaimType { get; }

        /// <summary>
        ///获取Claim值的可选列表，如果有的话，
         ///声明必须匹配。
        /// </summary>
        public IEnumerable<string> AllowedValues { get; }

        /// <summary>
        /// 根据指定的Claim要求来决定是否允许授权。
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ClaimsAuthorizationRequirement requirement)
        {
            if (context.User != null)
            {
                var found = false;
                if (requirement.AllowedValues == null || !requirement.AllowedValues.Any())
                {
                    found = context.User.Claims.Any(c => string.Equals(c.Type, requirement.ClaimType, StringComparison.OrdinalIgnoreCase));
                }
                else
                {
                    found = context.User.Claims.Any(c => string.Equals(c.Type, requirement.ClaimType, StringComparison.OrdinalIgnoreCase)
                                                        && requirement.AllowedValues.Contains(c.Value, StringComparer.Ordinal));
                }
                if (found)
                {
                    context.Succeed(requirement);
                }
            }
            return Task.CompletedTask;
        }
    }
```
### DefaultAuthorizationEvaluator
```
    /// <summary>
    /// 确定授权请求是否成功。
    /// </summary>
    public class DefaultAuthorizationEvaluator : IAuthorizationEvaluator
    {
        /// <summary>
        /// 确定授权结果是否成功。
        /// </summary>
        /// <param name="context">The authorization information.</param>
        /// <returns>The <see cref="AuthorizationResult"/>.</returns>
        public AuthorizationResult Evaluate(AuthorizationHandlerContext context)
            => context.HasSucceeded
                ? AuthorizationResult.Success()
                : AuthorizationResult.Failed(context.HasFailed
                    ? AuthorizationFailure.ExplicitFail()
                    : AuthorizationFailure.Failed(context.PendingRequirements));
    }
```
### DefaultAuthorizationHandlerContextFactory
```
    /// <summary>
    /// 用于提供<see cref =“ AuthorizationHandlerContext” />用于授权的类型。
    /// </summary>
    public class DefaultAuthorizationHandlerContextFactory : IAuthorizationHandlerContextFactory
    {
        /// <summary>
        /// 创建一个<see cref =“ AuthorizationHandlerContext” />用于授权。
        /// </summary>
        /// <param name="requirements">The requirements to evaluate.</param>
        /// <param name="user">The user to evaluate the requirements against.</param>
        /// <param name="resource">
        /// An optional resource the policy should be checked with.
        /// If a resource is not required for policy evaluation you may pass null as the value.
        /// </param>
        /// <returns>The <see cref="AuthorizationHandlerContext"/>.</returns>
        public virtual AuthorizationHandlerContext CreateContext(IEnumerable<IAuthorizationRequirement> requirements, ClaimsPrincipal user, object resource)
        {
            return new AuthorizationHandlerContext(requirements, user, resource);
        }
    }
```
### DefaultAuthorizationHandlerProvider
```
    /// <summary>
    /// 处理程序提供程序的默认实现，
     ///为授权请求提供<see cref =“ IAuthorizationHandler” />。
    /// </summary>
    public class DefaultAuthorizationHandlerProvider : IAuthorizationHandlerProvider
    {
        private readonly IEnumerable<IAuthorizationHandler> _handlers;

        /// <summary>
        /// Creates a new instance of <see cref="DefaultAuthorizationHandlerProvider"/>.
        /// </summary>
        /// <param name="handlers">The <see cref="IAuthorizationHandler"/>s.</param>
        public DefaultAuthorizationHandlerProvider(IEnumerable<IAuthorizationHandler> handlers)
        {
            if (handlers == null)
            {
                throw new ArgumentNullException(nameof(handlers));
            }

            _handlers = handlers;
        }

        public Task<IEnumerable<IAuthorizationHandler>> GetHandlersAsync(AuthorizationHandlerContext context)
            => Task.FromResult(_handlers);
    }
```
### DefaultAuthorizationPolicyProvider
```
    /// <summary>
    /// 策略提供者的默认实现，
     ///为特定名称提供<see cref =“ AuthorizationPolicy” />。
    /// </summary>
    public class DefaultAuthorizationPolicyProvider : IAuthorizationPolicyProvider
    {
        private readonly AuthorizationOptions _options;
        private Task<AuthorizationPolicy> _cachedDefaultPolicy;
        private Task<AuthorizationPolicy> _cachedFallbackPolicy;

        /// <summary>
        /// Creates a new instance of <see cref="DefaultAuthorizationPolicyProvider"/>.
        /// </summary>
        /// <param name="options">The options used to configure this instance.</param>
        public DefaultAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            _options = options.Value;
        }

        /// <summary>
        /// 获取默认的授权策略。
        /// </summary>
        /// <returns>The default authorization policy.</returns>
        public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
        {
            return GetCachedPolicy(ref _cachedDefaultPolicy, _options.DefaultPolicy);
        }

        /// <summary>
        /// 获取后备授权策略。
        /// </summary>
        /// <returns>The fallback authorization policy.</returns>
        public Task<AuthorizationPolicy> GetFallbackPolicyAsync()
        {
            return GetCachedPolicy(ref _cachedFallbackPolicy, _options.FallbackPolicy);
        }

        private Task<AuthorizationPolicy> GetCachedPolicy(ref Task<AuthorizationPolicy> cachedPolicy, AuthorizationPolicy currentPolicy)
        {
            var local = cachedPolicy;
            if (local == null || local.Result != currentPolicy)
            {
                cachedPolicy = local = Task.FromResult(currentPolicy);
            }
            return local;
        }

        /// <summary>
        /// 从给定的<paramref name =“ policyName” />获取<see cref =“ AuthorizationPolicy” />
        /// </summary>
        /// <param name="policyName">The policy name to retrieve.</param>
        /// <returns>The named <see cref="AuthorizationPolicy"/>.</returns>
        public virtual Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            // MVC caches policies specifically for this class, so this method MUST return the same policy per
            // policyName for every request or it could allow undesired access. It also must return synchronously.
            // A change to either of these behaviors would require shipping a patch of MVC as well.
            return Task.FromResult(_options.GetPolicy(policyName));
        }
    }
```
### DefaultAuthorizationService
```
    /// <summary>
    /// The default implementation of an <see cref="IAuthorizationService"/>.
    /// </summary>
    public class DefaultAuthorizationService : IAuthorizationService
    {
        private readonly AuthorizationOptions _options;
        private readonly IAuthorizationHandlerContextFactory _contextFactory;
        private readonly IAuthorizationHandlerProvider _handlers;
        private readonly IAuthorizationEvaluator _evaluator;
        private readonly IAuthorizationPolicyProvider _policyProvider;
        private readonly ILogger _logger;

        /// <summary>
        /// Creates a new instance of <see cref="DefaultAuthorizationService"/>.
        /// </summary>
        /// <param name="policyProvider"><see cref =“ IAuthorizationPolicyProvider” />用于提供策略.</param>
        /// <param name="handlers">用于实现<see cref =“ IAuthorizationRequirement” />的处理程序。</param>
        /// <param name="logger">The logger used to log messages, warnings and errors.</param>  
        /// <param name="contextFactory"><see cref =“ IAuthorizationHandlerContextFactory” />用于创建用于处理授权的上下文。</param>  
        /// <param name="evaluator"><see cref =“ IAuthorizationEvaluator” />用于确定授权是否成功.</param>  
        /// <param name="options">The <see cref="AuthorizationOptions"/> used.</param>  
        public DefaultAuthorizationService(IAuthorizationPolicyProvider policyProvider, IAuthorizationHandlerProvider handlers, ILogger<DefaultAuthorizationService> logger, IAuthorizationHandlerContextFactory contextFactory, IAuthorizationEvaluator evaluator, IOptions<AuthorizationOptions> options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            if (policyProvider == null)
            {
                throw new ArgumentNullException(nameof(policyProvider));
            }
            if (handlers == null)
            {
                throw new ArgumentNullException(nameof(handlers));
            }
            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }
            if (contextFactory == null)
            {
                throw new ArgumentNullException(nameof(contextFactory));
            }
            if (evaluator == null)
            {
                throw new ArgumentNullException(nameof(evaluator));
            }

            _options = options.Value;
            _handlers = handlers;
            _policyProvider = policyProvider;
            _logger = logger;
            _evaluator = evaluator;
            _contextFactory = contextFactory;
        }

        /// <summary>
        /// 检查用户是否满足指定资源的一组特定要求。
        /// </summary>
        /// <param name="user">用户根据评估要求。</param>
        /// <param name="resource">用于评估需求的资源.</param>
        /// <param name="requirements">评估要求.</param>
        /// <returns>
        /// 指示授权是否成功的标志。
         ///当用户满足策略时，此值为<value> true </ value>，否则为<value> false </ value>。
        /// </returns>
        public async Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, IEnumerable<IAuthorizationRequirement> requirements)
        {
            if (requirements == null)
            {
                throw new ArgumentNullException(nameof(requirements));
            }

            var authContext = _contextFactory.CreateContext(requirements, user, resource);
            var handlers = await _handlers.GetHandlersAsync(authContext);
            foreach (var handler in handlers)
            {
                await handler.HandleAsync(authContext);
                if (!_options.InvokeHandlersAfterFailure && authContext.HasFailed)
                {
                    break;
                }
            }

            var result = _evaluator.Evaluate(authContext);
            if (result.Succeeded)
            {
                _logger.UserAuthorizationSucceeded();
            }
            else
            {
                _logger.UserAuthorizationFailed();
            }
            return result;
        }

        /// <summary>
        /// Checks if a user meets a specific authorization policy.
        /// </summary>
        /// <param name="user">The user to check the policy against.</param>
        /// <param name="resource">The resource the policy should be checked with.</param>
        /// <param name="policyName">The name of the policy to check against a specific context.</param>
        /// <returns>
        /// A flag indicating whether authorization has succeeded.
        /// This value is <value>true</value> when the user fulfills the policy otherwise <value>false</value>.
        /// </returns>
        public async Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object resource, string policyName)
        {
            if (policyName == null)
            {
                throw new ArgumentNullException(nameof(policyName));
            }

            var policy = await _policyProvider.GetPolicyAsync(policyName);
            if (policy == null)
            {
                throw new InvalidOperationException($"No policy found: {policyName}.");
            }
            return await this.AuthorizeAsync(user, resource, policy);
        }
    }
```
### DenyAnonymousAuthorizationRequirement
```
    /// <summary>
    ///实现<see cref =“ IAuthorizationHandler” />和<see cref =“ IAuthorizationRequirement” />
     ///这要求必须对当前用户进行身份验证。
    /// </summary>
    public class DenyAnonymousAuthorizationRequirement : AuthorizationHandler<DenyAnonymousAuthorizationRequirement>, IAuthorizationRequirement
    {
        /// <summary>
        /// 根据特定要求来决定是否允许授权。
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, DenyAnonymousAuthorizationRequirement requirement)
        {
            var user = context.User;
            var userIsAnonymous =
                user?.Identity == null ||
                !user.Identities.Any(i => i.IsAuthenticated);
            if (!userIsAnonymous)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }
    }
```
### NameAuthorizationRequirement
```
    /// <summary>
    /// 实现<see cref =“ IAuthorizationHandler” />和<see cref =“ IAuthorizationRequirement” />
     ///要求当前用户名必须与指定值匹配。
    /// </summary>
    public class NameAuthorizationRequirement : AuthorizationHandler<NameAuthorizationRequirement>, IAuthorizationRequirement
    {
        /// <summary>
        /// Constructs a new instance of <see cref="NameAuthorizationRequirement"/>.
        /// </summary>
        /// <param name="requiredName">The required name that the current user must have.</param>
        public NameAuthorizationRequirement(string requiredName)
        {
            if (requiredName == null)
            {
                throw new ArgumentNullException(nameof(requiredName));
            }

            RequiredName = requiredName;
        }

        /// <summary>
        /// 获取当前用户必须具有的必需名称。
        /// </summary>
        public string RequiredName { get; }

        /// <summary>
        /// 根据特定要求来决定是否允许授权。
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, NameAuthorizationRequirement requirement)
        {
            if (context.User != null)
            {
                if (context.User.Identities.Any(i => string.Equals(i.Name, requirement.RequiredName)))
                {
                    context.Succeed(requirement);
                }
            }
            return Task.CompletedTask;
        }
    }
```
### OperationAuthorizationRequirement
```
    /// <summary>
    ///一个帮助程序类，提供有用的<see cref =“ IAuthorizationRequirement” />
     ///包含一个名称。
    /// </summary>
    public class OperationAuthorizationRequirement : IAuthorizationRequirement
    {
        /// <summary>
        /// The name of this instance of <see cref="IAuthorizationRequirement"/>.
        /// </summary>
        public string Name { get; set; }
    }
```
### PassThroughAuthorizationHandler
```
    /// <summary>
    /// 基础结构类，它允许<see cref =“ IAuthorizationRequirement” />
     ///成为自己的<see cref =“ IAuthorizationHandler” />。
    /// </summary>
    public class PassThroughAuthorizationHandler : IAuthorizationHandler
    {
        /// <summary>
        /// 决定是否允许授权。
        /// </summary>
        /// <param name="context">The authorization context.</param>
        public async Task HandleAsync(AuthorizationHandlerContext context)
        {
            foreach (var handler in context.Requirements.OfType<IAuthorizationHandler>())
            {
                await handler.HandleAsync(context);
            }
        }
    }
```
### RolesAuthorizationRequirement
```
    /// <summary>
    /// 实现<see cref =“ IAuthorizationHandler” />和<see cref =“ IAuthorizationRequirement” />
     ///，这至少需要一个角色声明，其值必须是任何允许的角色。
    /// </summary>
    public class RolesAuthorizationRequirement : AuthorizationHandler<RolesAuthorizationRequirement>, IAuthorizationRequirement
    {
        /// <summary>
        /// Creates a new instance of <see cref="RolesAuthorizationRequirement"/>.
        /// </summary>
        /// <param name="allowedRoles">A collection of allowed roles.</param>
        public RolesAuthorizationRequirement(IEnumerable<string> allowedRoles)
        {
            if (allowedRoles == null)
            {
                throw new ArgumentNullException(nameof(allowedRoles));
            }

            if (allowedRoles.Count() == 0)
            {
                throw new InvalidOperationException(Resources.Exception_RoleRequirementEmpty);
            }
            AllowedRoles = allowedRoles;
        }

        /// <summary>
        /// 获取允许的角色的集合。
        /// </summary>
        public IEnumerable<string> AllowedRoles { get; }

        /// <summary>
        /// 根据特定要求来决定是否允许授权。
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RolesAuthorizationRequirement requirement)
        {
            if (context.User != null)
            {
                bool found = false;
                if (requirement.AllowedRoles == null || !requirement.AllowedRoles.Any())
                {
                    // 评论：我们要在这里做什么？ 没有要求的角色是自动成功吗？
                }
                else
                {
                    found = requirement.AllowedRoles.Any(r => context.User.IsInRole(r));
                }
                if (found)
                {
                    context.Succeed(requirement);
                }
            }
            return Task.CompletedTask;
        }

    }
```