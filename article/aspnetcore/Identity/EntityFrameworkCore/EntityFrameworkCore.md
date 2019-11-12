|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [IdentityDbContext](#identitydbcontext)
* [IdentityEntityFrameworkBuilderExtensions](#identityentityframeworkbuilderextensions)
* [IdentityUserContext](#identityusercontext)

###  IdentityDbContext
```
    /// <summary>
    /// 用于标识的Entity Framework数据库上下文的基类。
    /// </summary>
    public class IdentityDbContext : IdentityDbContext<IdentityUser, IdentityRole, string>
    {
        /// <summary>
        /// 初始化<see cref =“ IdentityDbContext” />的新实例。
        /// </summary>
        /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
        public IdentityDbContext(DbContextOptions options) : base(options) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityDbContext" /> class.
        /// </summary>
        protected IdentityDbContext() { }
    }


        /// <summary>
    ///用于标识的Entity Framework数据库上下文的基类。
    /// </summary>
    /// <typeparam name="TUser">用户对象的类型。</typeparam>
    public class IdentityDbContext<TUser> : IdentityDbContext<TUser, IdentityRole, string> where TUser : IdentityUser
    {
        /// <summary>
        /// Initializes a new instance of <see cref="IdentityDbContext"/>.
        /// </summary>
        /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
        public IdentityDbContext(DbContextOptions options) : base(options) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityDbContext" /> class.
        /// </summary>
        protected IdentityDbContext() { }
    }

        /// <summary>
    ///用于标识的Entity Framework数据库上下文的基类。
    /// </summary>
    /// <typeparam name="TUser">用户对象的类型。</typeparam>
    /// <typeparam name="TRole">角色对象的类型。</typeparam>
    /// <typeparam name="TKey">用户和角色的主键的类型。</typeparam>
    public class IdentityDbContext<TUser, TRole, TKey> : IdentityDbContext<TUser, TRole, TKey, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityRoleClaim<TKey>, IdentityUserToken<TKey>>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Initializes a new instance of the db context.
        /// </summary>
        /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
        public IdentityDbContext(DbContextOptions options) : base(options) { }

        /// <summary>
        /// Initializes a new instance of the class.
        /// </summary>
        protected IdentityDbContext() { }
    }

        /// <summary>
    /// 用于标识的Entity Framework数据库上下文的基类。
    /// </summary>
    /// <typeparam name="TUser">用户对象的类型.</typeparam>
    /// <typeparam name="TRole">角色对象的类型.</typeparam>
    /// <typeparam name="TKey">用户和角色的主键的类型。</typeparam>
    /// <typeparam name="TUserClaim">用户声明对象的类型。</typeparam>
    /// <typeparam name="TUserRole">用户角色对象的类型.</typeparam>
    /// <typeparam name="TUserLogin">用户登录对象的类型。</typeparam>
    /// <typeparam name="TRoleClaim">角色声明对象的类型。</typeparam>
    /// <typeparam name="TUserToken">用户令牌对象的类型.</typeparam>
    public abstract class IdentityDbContext<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken> : IdentityUserContext<TUser, TKey, TUserClaim, TUserLogin, TUserToken>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TUserClaim : IdentityUserClaim<TKey>
        where TUserRole : IdentityUserRole<TKey>
        where TUserLogin : IdentityUserLogin<TKey>
        where TRoleClaim : IdentityRoleClaim<TKey>
        where TUserToken : IdentityUserToken<TKey>
    {
        /// <summary>
        /// Initializes a new instance of the class.
        /// </summary>
        /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
        public IdentityDbContext(DbContextOptions options) : base(options) { }

        /// <summary>
        /// Initializes a new instance of the class.
        /// </summary>
        protected IdentityDbContext() { }

        /// <summary>
        /// 获取或设置用户角色的<see cref =“ DbSet {TEntity}”“ />。
        /// </summary>
        public virtual DbSet<TUserRole> UserRoles { get; set; }

        /// <summary>
        /// 获取或设置角色的<see cref =“ DbSet {TEntity}”“ />。
        /// </summary>
        public virtual DbSet<TRole> Roles { get; set; }

        /// <summary>
        ///获取或设置角色声明的<see cref =“ DbSet {TEntity}”“ />。
        /// </summary>
        public virtual DbSet<TRoleClaim> RoleClaims { get; set; }

        /// <summary>
        /// 配置身份框架所需的架构。
        /// </summary>
        /// <param name="builder">
        /// The builder being used to construct the model for this context.
        /// </param>
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.Entity<TUser>(b =>
            {
                b.HasMany<TUserRole>().WithOne().HasForeignKey(ur => ur.UserId).IsRequired();
            });

            builder.Entity<TRole>(b =>
            {
                b.HasKey(r => r.Id);
                b.HasIndex(r => r.NormalizedName).HasName("RoleNameIndex").IsUnique();
                b.ToTable("AspNetRoles");
                b.Property(r => r.ConcurrencyStamp).IsConcurrencyToken();

                b.Property(u => u.Name).HasMaxLength(256);
                b.Property(u => u.NormalizedName).HasMaxLength(256);

                b.HasMany<TUserRole>().WithOne().HasForeignKey(ur => ur.RoleId).IsRequired();
                b.HasMany<TRoleClaim>().WithOne().HasForeignKey(rc => rc.RoleId).IsRequired();
            });

            builder.Entity<TRoleClaim>(b =>
            {
                b.HasKey(rc => rc.Id);
                b.ToTable("AspNetRoleClaims");
            });

            builder.Entity<TUserRole>(b =>
            {
                b.HasKey(r => new { r.UserId, r.RoleId });
                b.ToTable("AspNetUserRoles");
            });
        }
    }
```
### IdentityEntityFrameworkBuilderExtensions
```
    /// <summary>
    /// 包含对<see cref =“ IdentityBuilder” />的扩展方法，用于添加实体框架存储。
    /// </summary>
    public static class IdentityEntityFrameworkBuilderExtensions
    {
        /// <summary>
        /// 添加身份信息存储的Entity Framework实现。
        /// </summary>
        /// <typeparam name="TContext">使用的实体框架数据库上下文.</typeparam>
        /// <param name="builder">此方法扩展的<see cref =“ IdentityBuilder” />实例。</param>
        /// <returns>此方法扩展的<see cref =“ IdentityBuilder” />实例。</returns>
        public static IdentityBuilder AddEntityFrameworkStores<TContext>(this IdentityBuilder builder)
            where TContext : DbContext
        {
            AddStores(builder.Services, builder.UserType, builder.RoleType, typeof(TContext));
            return builder;
        }

        private static void AddStores(IServiceCollection services, Type userType, Type roleType, Type contextType)
        {
            var identityUserType = FindGenericBaseType(userType, typeof(IdentityUser<>));
            if (identityUserType == null)
            {
                throw new InvalidOperationException(Resources.NotIdentityUser);
            }
       //获取此类型的泛型类型参数的数组。
            var keyType = identityUserType.GenericTypeArguments[0];

            if (roleType != null)
            {
                var identityRoleType = FindGenericBaseType(roleType, typeof(IdentityRole<>));
                if (identityRoleType == null)
                {
                    throw new InvalidOperationException(Resources.NotIdentityRole);
                }

                Type userStoreType = null;
                Type roleStoreType = null;
                var identityContext = FindGenericBaseType(contextType, typeof(IdentityDbContext<,,,,,,,>));
                if (identityContext == null)
                {
                    // 如果它是自定义DbContext，我们只能添加默认POCO
                    userStoreType = typeof(UserStore<,,,>).MakeGenericType(userType, roleType, contextType, keyType);
                    roleStoreType = typeof(RoleStore<,,>).MakeGenericType(roleType, contextType, keyType);
                }
                else
                {
                    userStoreType = typeof(UserStore<,,,,,,,,>).MakeGenericType(userType, roleType, contextType,
                        identityContext.GenericTypeArguments[2],
                        identityContext.GenericTypeArguments[3],
                        identityContext.GenericTypeArguments[4],
                        identityContext.GenericTypeArguments[5],
                        identityContext.GenericTypeArguments[7],
                        identityContext.GenericTypeArguments[6]);
                    roleStoreType = typeof(RoleStore<,,,,>).MakeGenericType(roleType, contextType,
                        identityContext.GenericTypeArguments[2],
                        identityContext.GenericTypeArguments[4],
                        identityContext.GenericTypeArguments[6]);
                }
                services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
                services.TryAddScoped(typeof(IRoleStore<>).MakeGenericType(roleType), roleStoreType);
            }
            else
            {   // No Roles
                Type userStoreType = null;
                var identityContext = FindGenericBaseType(contextType, typeof(IdentityUserContext<,,,,>));
                if (identityContext == null)
                {
                    // If its a custom DbContext, we can only add the default POCOs
                    userStoreType = typeof(UserOnlyStore<,,>).MakeGenericType(userType, contextType, keyType);
                }
                else
                {
                    userStoreType = typeof(UserOnlyStore<,,,,,>).MakeGenericType(userType, contextType,
                        identityContext.GenericTypeArguments[1],
                        identityContext.GenericTypeArguments[2],
                        identityContext.GenericTypeArguments[3],
                        identityContext.GenericTypeArguments[4]);
                }
                services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
            }

        }

        private static TypeInfo FindGenericBaseType(Type currentType, Type genericBaseType)
        {
            var type = currentType;
            while (type != null)
            {
                //返回指定类型的System.Reflection.TypeInfo表示形式。
                var typeInfo = type.GetTypeInfo();
                //获取一个值，该值指示当前类型是否为通用类型。
                返回一个System.Type对象，该对象表示一个通用类型定义，
         //可以构造当前的泛型类型。
                var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
                if (genericType != null && genericType == genericBaseType)
                {
                    return typeInfo;
                }
                type = type.BaseType;
            }
            return null;
        }
    }
```
### IdentityUserContext
```
    /// <summary>
    /// 用于标识的Entity Framework数据库上下文的基类。
    /// </summary>
    /// <typeparam name="TUser">用户对象的类型.</typeparam>
    public class IdentityUserContext<TUser> : IdentityUserContext<TUser, string> where TUser : IdentityUser
    {
        /// <summary>
        /// Initializes a new instance of <see cref="IdentityUserContext{TUser}"/>.
        /// </summary>
        /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
        public IdentityUserContext(DbContextOptions options) : base(options) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityUserContext{TUser}" /> class.
        /// </summary>
        protected IdentityUserContext() { }
    }

        /// <summary>
    /// 用于标识的Entity Framework数据库上下文的基类。
    /// </summary>
    /// <typeparam name="TUser">用户对象的类型.</typeparam>
    /// <typeparam name="TKey">用户和角色的主键的类型。</typeparam>
    public class IdentityUserContext<TUser, TKey> : IdentityUserContext<TUser, TKey, IdentityUserClaim<TKey>, IdentityUserLogin<TKey>, IdentityUserToken<TKey>>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Initializes a new instance of the db context.
        /// </summary>
        /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
        public IdentityUserContext(DbContextOptions options) : base(options) { }

        /// <summary>
        /// Initializes a new instance of the class.
        /// </summary>
        protected IdentityUserContext() { }
    }

        /// <summary>
    ///用于标识的Entity Framework数据库上下文的基类。
    /// </summary>
    /// <typeparam name="TUser">用户对象的类型.</typeparam>
    /// <typeparam name="TKey">用户和角色的主键类型.</typeparam>
    /// <typeparam name="TUserClaim">用户声明对象的类型。</typeparam>
    /// <typeparam name="TUserLogin">用户登录对象的类型。</typeparam>
    /// <typeparam name="TUserToken">用户令牌对象的类型。</typeparam>
    public abstract class IdentityUserContext<TUser, TKey, TUserClaim, TUserLogin, TUserToken> : DbContext
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
        where TUserClaim : IdentityUserClaim<TKey>
        where TUserLogin : IdentityUserLogin<TKey>
        where TUserToken : IdentityUserToken<TKey>
    {
        /// <summary>
        /// Initializes a new instance of the class.
        /// </summary>
        /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
        public IdentityUserContext(DbContextOptions options) : base(options) { }

        /// <summary>
        /// Initializes a new instance of the class.
        /// </summary>
        protected IdentityUserContext() { }

        /// <summary>
        /// 获取或设置用户的<see cref =“ DbSet {TEntity}”“ />。
        /// </summary>
        public virtual DbSet<TUser> Users { get; set; }

        /// <summary>
        ///获取或设置用户声明的<see cref =“ DbSet {TEntity}” /> />。
        /// </summary>
        public virtual DbSet<TUserClaim> UserClaims { get; set; }

        /// <summary>
        ///获取或设置用户登录名的<see cref =“ DbSet {TEntity}”“ />。
        /// </summary>
        public virtual DbSet<TUserLogin> UserLogins { get; set; }

        /// <summary>
        /// 获取或设置用户令牌的<see cref =“ DbSet {TEntity}”“ />。
        /// </summary>
        public virtual DbSet<TUserToken> UserTokens { get; set; }

        private StoreOptions GetStoreOptions() => this.GetService<IDbContextOptions>()
                            .Extensions.OfType<CoreOptionsExtension>()
                            .FirstOrDefault()?.ApplicationServiceProvider
                            ?.GetService<IOptions<IdentityOptions>>()
                            ?.Value?.Stores;

        private class PersonalDataConverter : ValueConverter<string, string>
        {
            public PersonalDataConverter(IPersonalDataProtector protector) : base(s => protector.Protect(s), s => protector.Unprotect(s), default)
            { }
        }

        /// <summary>
        /// Configures the schema needed for the identity framework.
        /// </summary>
        /// <param name="builder">
        /// The builder being used to construct the model for this context.
        /// </param>
        protected override void OnModelCreating(ModelBuilder builder)
        {
            var storeOptions = GetStoreOptions();
            var maxKeyLength = storeOptions?.MaxLengthForKeys ?? 0;
            var encryptPersonalData = storeOptions?.ProtectPersonalData ?? false;
            PersonalDataConverter converter = null;

            builder.Entity<TUser>(b =>
            {
                b.HasKey(u => u.Id);
                b.HasIndex(u => u.NormalizedUserName).HasName("UserNameIndex").IsUnique();
                b.HasIndex(u => u.NormalizedEmail).HasName("EmailIndex");
                b.ToTable("AspNetUsers");
                b.Property(u => u.ConcurrencyStamp).IsConcurrencyToken();

                b.Property(u => u.UserName).HasMaxLength(256);
                b.Property(u => u.NormalizedUserName).HasMaxLength(256);
                b.Property(u => u.Email).HasMaxLength(256);
                b.Property(u => u.NormalizedEmail).HasMaxLength(256);

                if (encryptPersonalData)
                {
                    converter = new PersonalDataConverter(this.GetService<IPersonalDataProtector>());
                    var personalDataProps = typeof(TUser).GetProperties().Where(
                                    prop => Attribute.IsDefined(prop, typeof(ProtectedPersonalDataAttribute)));
                    foreach (var p in personalDataProps)
                    {
                        if (p.PropertyType != typeof(string))
                        {
                            throw new InvalidOperationException(Resources.CanOnlyProtectStrings);
                        }
                        b.Property(typeof(string), p.Name).HasConversion(converter);
                    }
                }

                b.HasMany<TUserClaim>().WithOne().HasForeignKey(uc => uc.UserId).IsRequired();
                b.HasMany<TUserLogin>().WithOne().HasForeignKey(ul => ul.UserId).IsRequired();
                b.HasMany<TUserToken>().WithOne().HasForeignKey(ut => ut.UserId).IsRequired();
            });

            builder.Entity<TUserClaim>(b =>
            {
                b.HasKey(uc => uc.Id);
                b.ToTable("AspNetUserClaims");
            });

            builder.Entity<TUserLogin>(b =>
            {
                b.HasKey(l => new { l.LoginProvider, l.ProviderKey });

                if (maxKeyLength > 0)
                {
                    b.Property(l => l.LoginProvider).HasMaxLength(maxKeyLength);
                    b.Property(l => l.ProviderKey).HasMaxLength(maxKeyLength);
                }

                b.ToTable("AspNetUserLogins");
            });

            builder.Entity<TUserToken>(b => 
            {
                b.HasKey(t => new { t.UserId, t.LoginProvider, t.Name });

                if (maxKeyLength > 0)
                {
                    b.Property(t => t.LoginProvider).HasMaxLength(maxKeyLength);
                    b.Property(t => t.Name).HasMaxLength(maxKeyLength);
                }

                if (encryptPersonalData)
                {
                    var tokenProps = typeof(TUserToken).GetProperties().Where(
                                    prop => Attribute.IsDefined(prop, typeof(ProtectedPersonalDataAttribute)));
                    foreach (var p in tokenProps)
                    {
                        if (p.PropertyType != typeof(string))
                        {
                            throw new InvalidOperationException(Resources.CanOnlyProtectStrings);
                        }
                        b.Property(typeof(string), p.Name).HasConversion(converter);
                    }
                }

                b.ToTable("AspNetUserTokens");
            });
        }
    }
```