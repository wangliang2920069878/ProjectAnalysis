|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [IdentityRole](#identityrole)
* [IdentityRoleClaim](#identityroleclaim)
* [IdentityUser](#identityuser)
* [IdentityUserClaim](#identityuserclaim)
* [IdentityUserLogin](#identityuserlogin)
* [IdentityUserRole](#identityuserrole)
* [IdentityUserToken](#identityusertoken)
* [RoleStoreBase](#rolestorebase)
* [UserStoreBase](#userstorebase)
### IdentityRole
```
    /// <summary>
    /// <see cref =“ IdentityRole {TKey}” />的默认实现，它使用字符串作为主键。
    /// </summary>
    public class IdentityRole : IdentityRole<string>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="IdentityRole"/>.
        /// </summary>
        /// <remarks>
        /// id属性被初始化为新的GUID字符串值。
        /// </remarks>
        public IdentityRole()
        {
            Id = Guid.NewGuid().ToString();
        }

        /// <summary>
        /// 初始化<see cref =“ IdentityRole” />的新实例。
        /// </summary>
        /// <param name="roleName">The role name.</param>
        /// <remarks>
        /// id属性被初始化为新的GUID字符串值。
        /// </remarks>
        public IdentityRole(string roleName) : this()
        {
            Name = roleName;
        }
    }

    /// <summary>
    ///代表身份系统中的角色
    /// </summary>
    /// <typeparam name="TKey">用于角色主键的类型。</typeparam>
    public class IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="IdentityRole{TKey}"/>.
        /// </summary>
        public IdentityRole() { }

        /// <summary>
        /// Initializes a new instance of <see cref="IdentityRole{TKey}"/>.
        /// </summary>
        /// <param name="roleName">The role name.</param>
        public IdentityRole(string roleName) : this()
        {
            Name = roleName;
        }

        /// <summary>
        /// 获取或设置此角色的主键。
        /// </summary>
        public virtual TKey Id { get; set; }

        /// <summary>
        /// 获取或设置此角色的名称。
        /// </summary>
        public virtual string Name { get; set; }

        /// <summary>
        ///获取或设置此角色的标准化名称。
        /// </summary>
        public virtual string NormalizedName { get; set; }

        /// <summary>
        /// 一个随机值，只要将角色保留到存储中就应该更改
        /// </summary>
        public virtual string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// 返回角色的名称。
        /// </summary>
        /// <returns>The name of the role.</returns>
        public override string ToString()
        {
            return Name;
        }
    }
```
### IdentityRoleClaim
```
    /// <summary>
    /// 表示授予角色中所有用户的声明。
    /// </summary>
    /// <typeparam name="TKey">与此声明关联的角色的主键的类型.</typeparam>
    public class IdentityRoleClaim<TKey> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// 获取或设置此角色声明的标识符。
        /// </summary>
        public virtual int Id { get; set; }

        /// <summary>
        /// 获取或设置与此声明关联的角色的主键。
        /// </summary>
        public virtual TKey RoleId { get; set; }

        /// <summary>
        ///获取或设置此声明的声明类型。
        /// </summary>
        public virtual string ClaimType { get; set; }

        /// <summary>
        /// 获取或设置此Claim的Claim值。
        /// </summary>
        public virtual string ClaimValue { get; set; }

        /// <summary>
        /// 使用类型和值构造新的声明。
        /// </summary>
        /// <returns>The <see cref="Claim"/> that was produced.</returns>
        public virtual Claim ToClaim()
        {
            return new Claim(ClaimType, ClaimValue);
        }

        /// <summary>
        ///通过从其他Claim中复制ClaimType和ClaimValue进行初始化。
        /// </summary>
        /// <param name="other">The claim to initialize from.</param>
        public virtual void InitializeFromClaim(Claim other)
        {
            ClaimType = other?.Type;
            ClaimValue = other?.Value;
        }
    }
```
### IdentityUser
```
    /// <summary>
    /// <see cref =“ IdentityUser {TKey}” />的默认实现，该实现使用字符串作为主键。
    /// </summary>
    public class IdentityUser : IdentityUser<string>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="IdentityUser"/>.
        /// </summary>
        /// <remarks>
        /// id属性被初始化为新的GUID字符串值。
        /// </remarks>
        public IdentityUser()
        {
            Id = Guid.NewGuid().ToString();
            SecurityStamp = Guid.NewGuid().ToString();
        }

        /// <summary>
        /// Initializes a new instance of <see cref="IdentityUser"/>.
        /// </summary>
        /// <param name="userName">The user name.</param>
        /// <remarks>
        /// id属性被初始化为新的GUID字符串值。
        /// </remarks>
        public IdentityUser(string userName) : this()
        {
            UserName = userName;
        }
    }

    /// <summary>
    /// 代表身份系统中的用户
    /// </summary>
    /// <typeparam name="TKey">The type used for the primary key for the user.</typeparam>
    public class IdentityUser<TKey> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="IdentityUser{TKey}"/>.
        /// </summary>
        public IdentityUser() { }

        /// <summary>
        /// Initializes a new instance of <see cref="IdentityUser{TKey}"/>.
        /// </summary>
        /// <param name="userName">The user name.</param>
        public IdentityUser(string userName) : this()
        {
            UserName = userName;
        }

        /// <summary>
        /// 获取或设置此用户的主键。
        /// </summary>
        [PersonalData]
        public virtual TKey Id { get; set; }

        /// <summary>
        /// 获取或设置该用户的用户名。
        /// </summary>
        [ProtectedPersonalData]
        public virtual string UserName { get; set; }

        /// <summary>
        /// 获取或设置此用户的标准化用户名。
        /// </summary>
        public virtual string NormalizedUserName { get; set; }

        /// <summary>
        /// 获取或设置该用户的电子邮件地址。
        /// </summary>
        [ProtectedPersonalData]
        public virtual string Email { get; set; }

        /// <summary>
        /// 获取或设置此用户的规范化电子邮件地址。
        /// </summary>
        public virtual string NormalizedEmail { get; set; }

        /// <summary>
        /// 获取或设置一个标志。
        /// </summary>
        /// <value>如果已确认电子邮件地址，则为true，否则为false。</value>
        [PersonalData]
        public virtual bool EmailConfirmed { get; set; }

        /// <summary>
        ///获取或设置此用户的密码的散列表示形式。
        /// </summary>
        public virtual string PasswordHash { get; set; }

        /// <summary>
        /// 用户更改凭据时必须更改的随机值（更改密码，删除登录名）
        /// </summary>
        public virtual string SecurityStamp { get; set; }

        /// <summary>
        ///用户持续存储时必须更改的随机值
        /// </summary>
        public virtual string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        ///获取或设置用户的电话号码。
        /// </summary>
        [ProtectedPersonalData]
        public virtual string PhoneNumber { get; set; }

        /// <summary>
        /// 获取或设置一个标志，该标志指示用户是否已确认其电话地址。
        /// </summary>
        /// <value>True if the telephone number has been confirmed, otherwise false.</value>
        [PersonalData]
        public virtual bool PhoneNumberConfirmed { get; set; }

        /// <summary>
        /// Gets or sets a flag indicating if two factor authentication is enabled for this user.
        /// </summary>
        /// <value>True if 2fa is enabled, otherwise false.</value>
        [PersonalData]
        public virtual bool TwoFactorEnabled { get; set; }

        /// <summary>
        /// 当任何用户锁定结束时，以UTC获取或设置日期和时间。
        /// </summary>
        /// <remarks>
        /// A value in the past means the user is not locked out.
        /// </remarks>
        public virtual DateTimeOffset? LockoutEnd { get; set; }

        /// <summary>
        /// 如果可以将用户锁定，则获取或设置一个标志。
        /// </summary>
        /// <value>如果可以将用户锁定，则为true，否则为false.</value>
        public virtual bool LockoutEnabled { get; set; }

        /// <summary>
        ///获取或设置当前用户失败的登录尝试次数。
        /// </summary>
        public virtual int AccessFailedCount { get; set; }

        /// <summary>
        /// Returns the username for this user.
        /// </summary>
        public override string ToString()
            => UserName;
    }
```
### IdentityUserClaim
```
    /// <summary>
    /// 代表用户拥有的声明。
    /// </summary>
    /// <typeparam name="TKey">用于此用户的主键的类型拥有此声明。</typeparam>
    public class IdentityUserClaim<TKey> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// 获取或设置此用户声明的标识符。
        /// </summary>
        public virtual int Id { get; set; }

        /// <summary>
        /// 获取或设置与此声明关联的用户的主键。
        /// </summary>
        public virtual TKey UserId { get; set; }

        /// <summary>
        /// 获取或设置此声明的声明类型。
        /// </summary>
        public virtual string ClaimType { get; set; }

        /// <summary>
        ///获取或设置此声明的声明值。
        /// </summary>
        public virtual string ClaimValue { get; set; }

        /// <summary>
        /// 将实体转换为声明实例。
        /// </summary>
        /// <returns></returns>
        public virtual Claim ToClaim()
        {
            return new Claim(ClaimType, ClaimValue);
        }

        /// <summary>
        /// 从声明中读取类型和值。
        /// </summary>
        /// <param name="claim"></param>
        public virtual void InitializeFromClaim(Claim claim)
        {
            ClaimType = claim.Type;
            ClaimValue = claim.Value;
        }
    }
```
### IdentityUserLogin
```
    /// <summary>
    /// 代表用户的登录名及其关联的提供程序。
    /// </summary>
    /// <typeparam name="TKey">与此登录关联的用户主键的类型。</typeparam>
    public class IdentityUserLogin<TKey> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// 获取或设置登录名的登录提供程序（例如，facebook，google）
        /// </summary>
        public virtual string LoginProvider { get; set; }

        /// <summary>
        /// 获取或设置此登录名的唯一提供程序标识符。
        /// </summary>
        public virtual string ProviderKey { get; set; }

        /// <summary>
        /// 获取或设置此登录名在UI中使用的友好名称。
        /// </summary>
        public virtual string ProviderDisplayName { get; set; }

        /// <summary>
        ///获取或设置与此登录关联的用户的主键。
        /// </summary>
        public virtual TKey UserId { get; set; }
    }
```
### IdentityUserRole
```
    /// <summary>
    /// 表示用户和角色之间的链接。
    /// </summary>
    /// <typeparam name="TKey">The type of the primary key used for users and roles.</typeparam>
    public class IdentityUserRole<TKey> where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// 获取或设置链接到角色的用户的主键。
        /// </summary>
        public virtual TKey UserId { get; set; }

        /// <summary>
        ///获取或设置链接到用户的角色的主键。
        /// </summary>
        public virtual TKey RoleId { get; set; }
    }
```
### IdentityUserToken
```
    /// <summary>
    /// 代表用户的身份验证令牌。
    /// </summary>
    /// <typeparam name="TKey">用户使用的主键的类型。</typeparam>
    public class IdentityUserToken<TKey> where TKey : IEquatable<TKey>
    {
        /// <summary>
        ///获取或设置属于令牌的用户的主键。
        /// </summary>
        public virtual TKey UserId { get; set; }

        /// <summary>
        /// 获取或设置此令牌来自的LoginProvider。
        /// </summary>
        public virtual string LoginProvider { get; set; }

        /// <summary>
        /// 获取或设置令牌的名称。
        /// </summary>
        public virtual string Name { get; set; }

        /// <summary>
        /// 获取或设置令牌值。
        /// </summary>
        [ProtectedPersonalData]
        public virtual string Value { get; set; }
    }
```
### RoleStoreBase
```
    /// <summary>
    /// 为角色创建一个持久性存储的新实例。
    /// </summary>
    /// <typeparam name="TRole">代表角色的类的类型。</typeparam>
    /// <typeparam name="TKey">角色的主键类型.</typeparam>
    /// <typeparam name="TUserRole">代表用户角色的类的类型.</typeparam>
    /// <typeparam name="TRoleClaim">代表角色声明的类的类型。</typeparam>
    public abstract class RoleStoreBase<TRole, TKey, TUserRole, TRoleClaim> :
        IQueryableRoleStore<TRole>,
        IRoleClaimStore<TRole>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TUserRole : IdentityUserRole<TKey>, new()
        where TRoleClaim : IdentityRoleClaim<TKey>, new()
    {
        /// <summary>
        /// Constructs a new instance of <see cref="RoleStoreBase{TRole, TKey, TUserRole, TRoleClaim}"/>.
        /// </summary>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public RoleStoreBase(IdentityErrorDescriber describer)
        {
            if (describer == null)
            {
                throw new ArgumentNullException(nameof(describer));
            }

            ErrorDescriber = describer;
        }

        private bool _disposed;

        /// <summary>
        ///获取或设置当前操作发生的任何错误<see cref =“ IdentityErrorDescriber” />。
        /// </summary>
        public IdentityErrorDescriber ErrorDescriber { get; set; }

        /// <summary>
        /// 在store中创建一个新角色作为异步操作。
        /// </summary>
        /// <param name="role">The role to create in the store.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>一个<see cref =“ Task {TResult}” /> />代表异步查询的<see cref =“ IdentityResult” />.</returns>
        public abstract Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken));

        /// <summary>
        /// 将商店中的角色更新为异步操作。
        /// </summary>
        /// <param name="role">The role to update in the store.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
        public abstract Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken));

        /// <summary>
        /// 作为异步操作从存储中删除角色。
        /// </summary>
        /// <param name="role">The role to delete from the store.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
        public abstract Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken));

        /// <summary>
        /// 作为异步操作获取存储中角色的ID。
        /// </summary>
        /// <param name="role">The role whose ID should be returned.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the ID of the role.</returns>
        public virtual Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            return Task.FromResult(ConvertIdToString(role.Id));
        }

        /// <summary>
        /// 获取存储中角色的名称作为异步操作。
        /// </summary>
        /// <param name="role">The role whose name should be returned.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the name of the role.</returns>
        public virtual Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            return Task.FromResult(role.Name);
        }

        /// <summary>
        ///将存储中角色的名称设置为异步操作。
        /// </summary>
        /// <param name="role">The role whose name should be set.</param>
        /// <param name="roleName">The name of the role.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public virtual Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            role.Name = roleName;
            return Task.CompletedTask;
        }

        /// <summary>
        /// 将提供的<paramref name =“ id” />转换为强类型键对象。
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey"/> representing the provided <paramref name="id"/>.</returns>
        public virtual TKey ConvertIdFromString(string id)
        {
            if (id == null)
            {
                return default(TKey);
            }
            return (TKey)TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
        }

        /// <summary>
        /// 将提供的<paramref name =“ id” />转换为其字符串表示形式。
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An <see cref="string"/> representation of the provided <paramref name="id"/>.</returns>
        public virtual string ConvertIdToString(TKey id)
        {
            if (id.Equals(default(TKey)))
            {
                return null;
            }
            return id.ToString();
        }

        /// <summary>
        /// 查找具有ID作为异步操作的角色。
        /// </summary>
        /// <param name="id">The role ID to look for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that result of the look up.</returns>
        public abstract Task<TRole> FindByIdAsync(string id, CancellationToken cancellationToken = default(CancellationToken));

        /// <summary>
        /// 查找具有指定标准化名称的角色作为异步操作。
        /// </summary>
        /// <param name="normalizedName">The normalized role name to look for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that result of the look up.</returns>
        public abstract Task<TRole> FindByNameAsync(string normalizedName, CancellationToken cancellationToken = default(CancellationToken));

        /// <summary>
        /// 获取角色的标准化名称作为异步操作。
        /// </summary>
        /// <param name="role">The role whose normalized name should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the name of the role.</returns>
        public virtual Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            return Task.FromResult(role.NormalizedName);
        }

        /// <summary>
        /// Set a role's normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose normalized name should be set.</param>
        /// <param name="normalizedName">The normalized name to set</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public virtual Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Throws if this class has been disposed.
        /// </summary>
        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        /// <summary>
        /// Dispose the stores
        /// </summary>
        public void Dispose() => _disposed = true;

        /// <summary>
        ///与异步操作中一样，获取与指定的<paramref name =“ role” />相关的声明。
        /// </summary>
        /// <param name="role">The role whose claims should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the claims granted to a role.</returns>
        public abstract Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken));

        /// <summary>
        ///将给定的<paramref name =“ role” />添加给<paramref name =“ claim” />。
        /// </summary>
        /// <param name="role">The role to add the claim to.</param>
        /// <param name="claim">The claim to add to the role.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public abstract Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken));

        /// <summary>
        /// 从指定的<paramref name =“ role” />中删除<paramref name =“ claim” />。
        /// </summary>
        /// <param name="role">The role to remove the claim from.</param>
        /// <param name="claim">The claim to remove from the role.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public abstract Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken));

        /// <summary>
        /// 角色的导航属性包含存储。
        /// </summary>
        public abstract IQueryable<TRole> Roles
        {
            get;
        }

        /// <summary>
        /// 创建一个代表角色声明的实体。
        /// </summary>
        /// <param name="role">The associated role.</param>
        /// <param name="claim">The associated claim.</param>
        /// <returns>The role claim entity.</returns>
        protected virtual TRoleClaim CreateRoleClaim(TRole role, Claim claim)
            => new TRoleClaim { RoleId = role.Id, ClaimType = claim.Type, ClaimValue = claim.Value };
    }
```