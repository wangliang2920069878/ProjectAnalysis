|Author|魍魉|
|---|---
|E-mail|2920069878@qq.com

****
## 目录
* [ILookupNormalizer](#ilookupnormalizer)
* [ILookupProtector](#ilookupprotector)
* [ILookupProtectorKeyRing](#ilookupprotectorkeyring)
* [IPasswordHasher](#ipasswordhasher)
* [IPasswordValidator](#ipasswordvalidator)
* [IPersonalDataProtector](#ipersonaldataprotector)
* [IProtectedUserStore](#iprotecteduserstore)
* [IQueryableRoleStore](#iqueryablerolestore)
* [IQueryableUserStore](#iqueryableuserstore)
* [IRoleClaimStore](#iroleclaimstore)
* [IRoleStore](#irolestore)
* [IRoleValidator](#irolevalidator)
* [IUserAuthenticationTokenStore](#iuserauthenticationtokenstore)
* [IUserAuthenticatorKeyStore](#iuserauthenticatorkeystore)
* [IUserClaimsPrincipalFactory](#iuserclaimsprincipalfactory)
* [IUserClaimStore](#iuserclaimstore)
* [IUserConfirmation](#iuserconfirmation)
* [IUserEmailStore](#iuseremailstore)
* [IUserLockoutStore](#iuserlockoutstore)
* [IUserLoginStore](#iuserloginstore)
* [IUserPasswordStore](#iuserpasswordstore)
* [IUserPhoneNumberStore](#iuserphonenumberstore)
* [IUserRoleStore](#iuserrolestore)
* [IUserSecurityStampStore](#iusersecuritystampstore)
* [IUserStore](#iuserstore)
* [IUserTwoFactorRecoveryCodeStore](#iusertwofactorrecoverycodestore)
* [IUserTwoFactorStore](#iusertwofactorstore)
* [IUserTwoFactorTokenProvider](#iusertwofactortokenprovider)
* [IUserValidator](#iuservalidator)
---
* [AuthenticatorTokenProvider](#authenticatortokenprovider)
* [Base32](#base32)
* [ClaimsIdentityOptions](#claimsidentityoptions)
* [DefaultPersonalDataProtector](#defaultpersonaldataprotector)
* [DefaultUserConfirmation](#defaultuserconfirmation)
* [EmailTokenProvider](#emailtokenprovider)
* [IdentityBuilder](#identitybuilder)
* [IdentityError](#identityerror)
* [IdentityErrorDescriber](#identityerrordescriber)
* [IdentityOptions](#identityoptions)
* [IdentityResult](#identityresult)
* [IdentityServiceCollectionExtensions](#identityservicecollectionextensions)
### ILookupNormalizer
```
    /// <summary>
    ///提供用于规范化密钥（电子邮件/名称）以进行查找的抽象。
    /// </summary>
    public interface ILookupNormalizer
    {
        /// <summary>
        /// 返回指定<paramref name =“ name” />的规范化表示。
        /// </summary>
        /// <param name="name">规范化的键。</param>
        /// <returns>指定的<paramref name =“ name” />的规范化表示。</returns>
        string NormalizeName(string name);

        /// <summary>
        /// 返回指定<paramref name =“ email” />的规范化表示。
        /// </summary>
        /// <param name="email">要规范化的电子邮件。</param>
        /// <returns>指定的归一化表示<paramref名称=“电子邮件” />。</returns>
        string NormalizeEmail(string email);

    }
```
### ILookupProtector
```
    /// <summary>
    /// 用于保护/取消保护具有特定密钥的查找。
    /// </summary>
    public interface ILookupProtector
    {
        /// <summary>
        /// 使用指定的密钥保护数据。
        /// </summary>
        /// <param name="keyId">The key to use.</param>
        /// <param name="data">The data to protect.</param>
        /// <returns>The protected data.</returns>
        string Protect(string keyId, string data);

        /// <summary>
        ///使用指定的密钥取消保护数据。
        /// </summary>
        /// <param name="keyId">The key to use.</param>
        /// <param name="data">The data to unprotect.</param>
        /// <returns>The original data.</returns>
        string Unprotect(string keyId, string data);
    }
```
### ILookupProtectorKeyRing
```
    /// <summary>
    ///用于管理命名密钥的抽象，用于保护查找。
    /// </summary>
    public interface ILookupProtectorKeyRing
    {
        /// <summary>
        /// 获取当前的密钥ID。
        /// </summary>
        string CurrentKeyId { get; }

        /// <summary>
        /// 返回一个特定的密钥。
        /// </summary>
        /// <param name="keyId">要获取的密钥的ID.</param>
        /// <returns>The key ring.</returns>
        string this[string keyId] { get; }

        /// <summary>
        /// 返回所有密钥ID。
        /// </summary>
        /// <returns>All of the key ids.</returns>
        IEnumerable<string> GetAllKeyIds();
    }
```
### IPasswordHasher
```
    /// <summary>
    /// 提供哈希密码的抽象。
    /// </summary>
    /// <typeparam name="TUser">用于表示用户的类型.</typeparam>
    public interface IPasswordHasher<TUser> where TUser : class
    {
        /// <summary>
        /// 返回指定的<paramref name =“ user” />所提供的<paramref name =“ password” />的哈希表示。
        /// </summary>
        /// <param name="user">要对其密码进行哈希处理的用户.</param>
        /// <param name="password">哈希密码.</param>
        /// <returns>指定的<paramref name =“ user” />所提供的<paramref name =“ password” />的哈希表示。</returns>
        string HashPassword(TUser user, string password);

        /// <summary>
        /// 返回一个<see cref =“ PasswordVerificationResult” />，指示密码哈希比较的结果。
        /// </summary>
        /// <param name="user">应验证其密码的用户。</param>
        /// <param name="hashedPassword">用户存储的密码的哈希值。</param>
        /// <param name="providedPassword">提供的用于比较的密码。</param>
        /// <returns><see cref =“ PasswordVerificationResult” />指示密码哈希比较的结果。</returns>
        /// <remarks>此方法的实现应与时间保持一致.</remarks>
        PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword);
    }
```
### IPasswordValidator
```
    /// <summary>
    /// 提供用于验证密码的抽象。
    /// </summary>
    /// <typeparam name="TUser">代表用户的类型.</typeparam>
    public interface IPasswordValidator<TUser> where TUser : class
    {
        /// <summary>
        /// 验证有关异步操作的密码。
        /// </summary>
        /// <param name="manager"><see cref =“ UserManager {TUser}” />从中检索<paramref name =“ user” />属性。</param>
        /// <param name="user">应验证其密码的用户.</param>
        /// <param name="password">提供的验证密码</param>
        /// <returns>代表异步操作的任务对象。</returns>
        Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password);
    }
```
### IPersonalDataProtector
```
    /// <summary>
    /// 提供用于个人数据加密的抽象。
    /// </summary>
    public interface IPersonalDataProtector
    {
        /// <summary>
        /// 保护数据。
        /// </summary>
        /// <param name="data">数据保护.</param>
        /// <returns>The protected data.</returns>
        string Protect(string data);

        /// <summary>
        /// 取消保护数据。
        /// </summary>
        /// <param name="data"></param>
        /// <returns>The unprotected data.</returns>
        string Unprotect(string data);
    }
```
### IProtectedUserStore
```
    /// <summary>
    ///标记界面，用于表示存储支持
<请参阅cref =“ StoreOptions.ProtectPersonalData” />标志。
    /// </summary>
    /// <typeparam name="TUser">代表用户的类型。</typeparam>
    public interface IProtectedUserStore<TUser> : IUserStore<TUser> where TUser : class
    { }
```
### IQueryableRoleStore
```
    /// <summary>
    /// 提供用于查询角色存储中角色的抽象。
    /// </summary>
    /// <typeparam name="TRole">The type encapsulating a role.</typeparam>
    public interface IQueryableRoleStore<TRole> : IRoleStore<TRole> where TRole : class
    {
        /// <summary>
        /// 返回到<see cref =“ IQueryable {T}” />角色集合。
        /// </summary>
        /// <value>An <see cref="IQueryable{T}"/> collection of roles.</value>
        IQueryable<TRole> Roles { get; }
    }
```
### IQueryableUserStore
```
    /// <summary>
    /// 提供用于向用户存储查询用户的抽象。
    /// </summary>
    /// <typeparam name="TUser">封装用户的类型。</typeparam>
    public interface IQueryableUserStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        /// Returns an <see cref="IQueryable{T}"/> collection of users.
        /// </summary>
        /// <value>An <see cref="IQueryable{T}"/> collection of users.</value>
        IQueryable<TUser> Users { get; }
    }
```
### IRoleClaimStore
```
    /// <summary>
    /// 为角色特定声明的存储提供抽象。
    /// </summary>
    /// <typeparam name="TRole">封装角色的类型。</typeparam>
    public interface IRoleClaimStore<TRole> : IRoleStore<TRole> where TRole : class
    {
        /// <summary>
        ///  获取指定的<paramref name =“ role” />拥有的<see cref =“ Claim” /> s的列表，以进行异步操作。
        /// </summary>
        /// <param name="role">取回role 的Claims </param>
        /// <param name="cancellationToken"><see cref =“ CancellationToken” />用于传播应取消该操作的通知。</param>
        /// <returns>
        /// 一个<see cref =“ Task {TResult}” />代表异步查询的结果，一个<see cref =“ Claim” />的列表。
        /// </returns>
        Task<IList<Claim>> GetClaimsAsync(TRole role,  CancellationToken cancellationToken = default(CancellationToken));

        /// <summary>
        /// 向异步操作中的角色添加新声明。
        /// </summary>
        /// <param name="role">向其添加claim的角色.</param>
        /// <param name="claim">The <see cref="Claim"/> to add.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>代表异步操作的任务对象.</returns>
        Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken));

        /// <summary>
        /// 从角色异步操作中删除claim。
        /// </summary>
        /// <param name="role">从中删除claim的角色.</param>
        /// <param name="claim">The <see cref="Claim"/> to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken));
    }
```
### IRoleStore
```
    /// <summary>
    /// 提供角色存储和管理的抽象。
    /// </summary>
    /// <typeparam name="TRole">代表角色的类型.</typeparam>
    public interface IRoleStore<TRole> : IDisposable where TRole : class
    {
        /// <summary>
        ///在存储中创建一个新角色作为异步操作。
        /// </summary>
        /// <param name="role">在存储中创建的角色.</param>
        /// <param name="cancellationToken"><see cref =“ CancellationToken” />用于传播应取消该操作的通知。</param>
        /// <returns>，<参考cref =“任务{TResult}” />代表异步查询的<see cref =“ IdentityResult” />。</returns>
        Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken);

        /// <summary>
        /// 将存储中的角色更新为异步操作。
        /// </summary>
        /// <param name="role">在存储中更新的角色。</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
        Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken);

        /// <summary>
        /// 作为异步操作从存储中删除角色。
        /// </summary>
        /// <param name="role">从存储中删除的角色</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous query.</returns>
        Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken);

        /// <summary>
        ///作为异步操作获取存储中角色的ID。
        /// </summary>
        /// <param name="role">应返回其ID的角色.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the ID of the role.</returns>
        Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken);

        /// <summary>
        /// 获取存储中角色的名称作为异步操作。
        /// </summary>
        /// <param name="role">The role whose name should be returned.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the name of the role.</returns>
        Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken);

        /// <summary>
        /// 将存储中角色的名称设置为异步操作。
        /// </summary>
        /// <param name="role">The role whose name should be set.</param>
        /// <param name="roleName">The name of the role.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken);

        /// <summary>
        /// 获取角色的标准化名称作为异步操作。
        /// </summary>
        /// <param name="role">The role whose normalized name should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the name of the role.</returns>
        Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken);

        /// <summary>
        /// 设置角色的标准化名称以进行异步操作。
        /// </summary>
        /// <param name="role">The role whose normalized name should be set.</param>
        /// <param name="normalizedName">The normalized name to set</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken);


        /// <summary>
        /// 查找具有ID作为异步操作的角色。
        /// </summary>
        /// <param name="roleId">The role ID to look for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that result of the look up.</returns>
        Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken);

        /// <summary>
        /// 查找具有指定标准化名称的角色作为异步操作。
        /// </summary>
        /// <param name="normalizedRoleName">The normalized role name to look for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that result of the look up.</returns>
        Task<TRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken);
    }
```
### IRoleValidator
```
    /// <summary>
    ///提供用于验证角色的抽象。
    /// </summary>
    /// <typeparam name="TRole">封装角色的类型.</typeparam>
    public interface IRoleValidator<TRole> where TRole : class
    {
        /// <summary>
        /// 将角色验证为异步操作。
        /// </summary>
        /// <param name="manager"><see cref =“ RoleManager {TRole}” />管理角色存储。</param>
        /// <param name="role">验证角色.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous validation.</returns>
        Task<IdentityResult> ValidateAsync(RoleManager<TRole> manager, TRole role);
    }
```
### IUserAuthenticationTokenStore
```
    /// <summary>
    /// 提供一种抽象来存储用户的身份验证令牌。
    /// </summary>
    /// <typeparam name="TUser">封装用户的类型.</typeparam>
    public interface IUserAuthenticationTokenStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        /// 设置特定用户的令牌值。
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="loginProvider">令牌的身份验证提供程序.</param>
        /// <param name="name">令牌的名称.</param>
        /// <param name="value">The value of the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns><see cref =“ Task” />代表异步操作.</returns>
        Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken);

        /// <summary>
        ///删除用户的令牌。
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="loginProvider">The authentication provider for the token.</param>
        /// <param name="name">The name of the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken);

        /// <summary>
        /// 返回令牌值。
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="loginProvider">The authentication provider for the token.</param>
        /// <param name="name">The name of the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken);
    }
```
### IUserAuthenticatorKeyStore
```
    /// <summary>
    /// 为存储有关用户身份验证器信息的存储提供抽象。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserAuthenticatorKeyStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        /// 为指定的<paramref name =“ user” />设置验证码。
        /// </summary>
        /// <param name="user">The user whose authenticator key should be set.</param>
        /// <param name="key">The authenticator key to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken);

        /// <summary>
        /// 获取指定的<paramref name =“ user” />的身份验证器密钥。
        /// </summary>
        /// <param name="user">The user whose security stamp should be set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the security stamp for the specified <paramref name="user"/>.</returns>
        Task<string> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken);
    }
```
### IUserClaimsPrincipalFactory
```
    /// <summary>
    ///为工厂提供抽象，以从用户创建<see cref =“ ClaimsPrincipal” />。
    /// </summary>
    /// <typeparam name="TUser">封装用户的类型.</typeparam>
    public interface IUserClaimsPrincipalFactory<TUser>
        where TUser : class
    {
        /// <summary>
        /// 从异步用户创建<see cref =“ ClaimsPrincipal” />。
        /// </summary>
        /// <param name="user">用户从创建一个<see cref =“ ClaimsPrincipal” />.</param>
        /// <returns>The <see cref="Task"/> 表示异步创建操作，其中包含<see cref =“ ClaimsPrincipal” />.</returns>
        Task<ClaimsPrincipal> CreateAsync(TUser user);
    }
```
### IUserClaimStore
```
    /// <summary>
    /// 为用户提供声明存储的抽象。
    /// </summary>
    /// <typeparam name="TUser">封装用户的类型.</typeparam>
    public interface IUserClaimStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        /// 获取指定的<paramref name =“ user” />拥有的<see cref =“ Claim” /> s的列表，以进行异步操作。
        /// </summary>
        /// <param name="user">The user whose claims to retrieve.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <see cref="Claim"/>s.
        /// </returns>
        Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 向用户异步操作添加声明。
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claims">The collection of <see cref="Claim"/>s to add.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken);

        /// <summary>
        ///将指定的<paramref name =“ user” />上给定的<paramref name =“ claim” />替换为<paramref name =“ newClaim” />
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param>
        /// <param name="claim">The claim to replace.</param>
        /// <param name="newClaim">The new claim to replace the existing <paramref name="claim"/> with.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken);

        /// <summary>
        /// 从给定的<paramref name =“ user” />中删除指定的<paramref name =“ claims” />。
        /// </summary>
        /// <param name="user">The user to remove the specified <paramref name="claims"/> from.</param>
        /// <param name="claims">A collection of <see cref="Claim"/>s to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken);

        /// <summary>
        /// 返回包含指定的<see cref =“ Claim” />的用户列表。
        /// </summary>
        /// <param name="claim">The claim to look for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <typeparamref name="TUser"/> who
        /// contain the specified claim.
        /// </returns>
        Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken);
    }
```
### IUserConfirmation
```
    /// <summary>
    /// 提供用于确认用户帐户的抽象。
    /// </summary>
    /// <typeparam name="TUser">封装用户的类型.</typeparam>
    public interface IUserConfirmation<TUser> where TUser : class
    {
        /// <summary>
        /// 确定是否确认指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> that can be used to retrieve user properties.</param>
        /// <param name="user">The user.</param>
        /// <returns>Whether the user is confirmed.</returns>
        Task<bool> IsConfirmedAsync(UserManager<TUser> manager, TUser user);
    }
```
### IUserEmailStore
```
    /// <summary>
    /// 提供用于存储和管理用户电子邮件地址的抽象。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserEmailStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        /// 为<paramref name =“ user” />设置<paramref name =“ email” />地址。
        /// </summary>
        /// <param name="user">The user whose email should be set.</param>
        /// <param name="email">The email to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken);

        /// <summary>
        /// 获取指定的<paramref name =“ user” />的电子邮件地址。
        /// </summary>
        /// <param name="user">The user whose email should be returned.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object containing the results of the asynchronous operation, the email address for the specified <paramref name="user"/>.</returns>
        Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 如果指定的<paramref name =“ user” />的电子邮件地址已经过验证，则获取标志；否则，则返回true
         ///错误。
        /// </summary>
        /// <param name="user">The user whose email confirmation status should be returned.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// 任务对象包含异步操作的结果，该标志指示指定的<paramref name =“ user” />的电子邮件地址
         ///是否已确认。
        /// </returns>
        Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 设置标志指示符，是否已确认指定的<paramref name =“ user” />的电子邮件地址。
        /// </summary>
        /// <param name="user">应该设置其电子邮件确认状态的用户。</param>
        /// <param name="confirmed">一个标志，指示是否已确认电子邮件地址，为true.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>代表异步操作的任务对象.</returns>
        Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken);

        /// <summary>
        ///获取与指定的标准化电子邮件地址关联的用户（如果有）。
        /// </summary>
        /// <param name="normalizedEmail">The normalized email address to return the user for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the user if any associated with the specified normalized email address.
        /// </returns>
        Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken);

        /// <summary>
        /// 返回指定<paramref name =“ user” />的规范化电子邮件。
        /// </summary>
        /// <param name="user">The user whose email address to retrieve.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the normalized email address if any associated with the specified user.
        /// </returns>
        Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        ///为指定的<paramref name =“ user” />设置规范化电子邮件。
        /// </summary>
        /// <param name="user">The user whose email address to set.</param>
        /// <param name="normalizedEmail">The normalized email to set for the specified <paramref name="user"/>.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken);
    }
```
### IUserLockoutStore
```
    /// <summary>
    ///提供用于存储信息的抽象，可用于实现帐户锁定，
     ///包括访问失败和锁定状态
    /// </summary>
    /// <typeparam name="TUser">The type that represents a user.</typeparam>
    public interface IUserLockoutStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        /// 获取用户的最后一次锁定（如果有）的最后一个<see cref =“ DateTimeOffset” />。
         ///过去任何时候都应该将用户锁定。
        /// </summary>
        /// <param name="user">The user whose lockout date should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// 一个<see cref =“ Task {TResult}” />代表异步查询的结果，一个<see cref =“ DateTimeOffset” />包含上次时间
         ///用户的锁定已过期（如果有）。
        /// </returns>
        Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 锁定用户，直到超过指定的结束日期。 在过去的瞬间设置日期可以解锁用户。
        /// </summary>
        /// <param name="user">The user whose lockout date should be set.</param>
        /// <param name="lockoutEnd">The <see cref="DateTimeOffset"/> after which the <paramref name="user"/>'s lockout should end.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken);

        /// <summary>
        /// 发生失败访问的记录，增加失败访问计数。
        /// </summary>
        /// <param name="user">The user whose cancellation count should be incremented.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the incremented failed access count.</returns>
        Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 重置用户的失败访问计数。
        /// </summary>
        /// <param name="user">The user whose failed access count should be reset.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        /// <remarks>This is typically called after the account is successfully accessed.</remarks>
        Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 检索指定的<paramref name =“ user” />的当前访问失败计数。
        /// </summary>
        /// <param name="user">The user whose failed access count should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the failed access count.</returns>
        Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        ///检索一个标志，该标志显示为指定用户启用的用户锁定。
        /// </summary>
        /// <param name="user">The user whose ability to be locked out should be returned.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, true if a user can be locked out, otherwise false.
        /// </returns>
        Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 如果可以锁定指定的<paramref name =“ user” />，则设置标志。
        /// </summary>
        /// <param name="user">应该设置用户的锁定能力.</param>
        /// <param name="enabled">一个标志，指示是否可以为指定的锁定启用.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken);
    }
```
### IUserLoginStore
```
    /// <summary>
    /// 提供用于存储映射外部登录信息的信息的抽象
     ///通过Microsoft帐户，Facebook等添加到用户帐户。
    /// </summary>
    /// <typeparam name="TUser">The type that represents a user.</typeparam>
    public interface IUserLoginStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        /// 将外部<see cref =“ UserLoginInfo” />添加到指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="user">The user to add the login to.</param>
        /// <param name="login">外部<see cref =“ UserLoginInfo” />添加到指定的<paramref name =“ user” />。</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken);

        /// <summary>
        ///尝试从指定的<paramref name =“ user” />中删除提供的登录信息。
         ///并返回一个标志。
        /// </summary>
        /// <param name="user">从中删除登录信息的用户。</param>
        /// <param name="loginProvider">该注册应被删除。</param>
        /// <param name="providerKey">外部登录提供程序为指定用户提供的密钥.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken);

        /// <summary>
        /// 检索指定的<param ref =“ user” />的关联登录。
        /// </summary>
        /// <param name="user">与用户关联的登录名进行检索。</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing a list of <see cref="UserLoginInfo"/> for the specified <paramref name="user"/>, if any.
        /// </returns>
        Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 检索与指定的登录提供程序和登录提供程序密钥关联的用户。
        /// </summary>
        /// <param name="loginProvider">The login provider who provided the <paramref name="providerKey"/>.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing the user, if any which matched the specified login provider and key.
        /// </returns>
        Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken);
    }
```
### IUserPasswordStore
```
    /// <summary>
    /// 为包含用户密码哈希的存储提供抽象。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserPasswordStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        ///为指定的<paramref name =“ user” />设置密码哈希。
        /// </summary>
        /// <param name="user">The user whose password hash to set.</param>
        /// <param name="passwordHash">The password hash to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken);

        /// <summary>
        ///获取指定的<paramref name =“ user” />的密码哈希。
        /// </summary>
        /// <param name="user">The user whose password hash to retrieve.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, returning the password hash for the specified <paramref name="user"/>.</returns>
        Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 获取一个标志，指示指定的<paramref name =“ user” />具有密码。
        /// </summary>
        /// <param name="user">用户返回一个标志，用于指示他们是否具有密码。</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, returning true if the specified <paramref name="user"/> has a password
        /// otherwise false.
        /// </returns>
        Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken);
    }
```
### IUserPhoneNumberStore
```
    /// <summary>
    /// 为包含用户电话号码的存储提供抽象。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserPhoneNumberStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        /// 设置指定的<paramref name =“ user” />的电话号码。
        /// </summary>
        /// <param name="user">The user whose telephone number should be set.</param>
        /// <param name="phoneNumber">The telephone number to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken);

        /// <summary>
        ///获取指定的<paramref name =“ user” />的电话号码（如果有）。
        /// </summary>
        /// <param name="user">The user whose telephone number should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the user's telephone number, if any.</returns>
        Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 获取一个标志，该标志指示是否已确认指定的<paramref name =“ user” />的电话号码。
        /// </summary>
        /// <param name="user">The user to return a flag for, indicating whether their telephone number is confirmed.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, returning true if the specified <paramref name="user"/> has a confirmed
        /// telephone number otherwise false.
        /// </returns>
        Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 如果已确认指定的<paramref name =“ user” />的电话号码，则设置一个标志。
        /// </summary>
        /// <param name="user">The user whose telephone number confirmation status should be set.</param>
        /// <param name="confirmed">指示用户的电话号码是否已被确认的标志。</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken);
    }
```
### IUserRoleStore
```
    /// <summary>
    ///提供用于将用户映射到角色的存储的抽象。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserRoleStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        /// 将指定的<paramref name =“ user” />添加到命名角色。
        /// </summary>
        /// <param name="user">The user to add to the named role.</param>
        /// <param name="roleName">The name of the role to add the user to.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken);

        /// <summary>
        /// 从命名角色中删除指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="user">The user to remove the named role from.</param>
        /// <param name="roleName">The name of the role to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken);

        /// <summary>
        /// 获取名为<specified> <paramref name =“ user” />的角色的列表。
        /// </summary>
        /// <param name="user">The user whose role names to retrieve.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a list of role names.</returns>
        Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 返回一个标志，指示指定的<paramref name =“ user” />是给定命名角色的成员。
        /// </summary>
        /// <param name="user">The user whose role membership should be checked.</param>
        /// <param name="roleName">The name of the role to be checked.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing a flag indicating whether the specified <paramref name="user"/> is
        /// a member of the named role.
        /// </returns>
        Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken);

        /// <summary>
        /// 返回属于指定角色的用户的列表。
        /// </summary>
        /// <param name="roleName">The name of the role whose membership should be returned.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing a list of users who are in the named role.
        /// </returns>
        Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken);
    }
```
### IUserSecurityStampStore
```
    /// <summary>
    /// 为存储用户安全标记的存储提供抽象。
    /// </summary>
    /// <typeparam name="TUser">封装用户的类型。</typeparam>
    public interface IUserSecurityStampStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        /// 为指定的<paramref name =“ user” />设置提供的安全性<paramref name =“ stamp” />。
        /// </summary>
        /// <param name="user">The user whose security stamp should be set.</param>
        /// <param name="stamp">The security stamp to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken);

        /// <summary>
        /// 获取指定的<paramref name =“ user” />的安全标记。
        /// </summary>
        /// <param name="user">The user whose security stamp should be set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the security stamp for the specified <paramref name="user"/>.</returns>
        Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken);
    }
```
### IUserStore
```
    /// <summary>
    /// 为管理用户帐户的存储提供抽象。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserStore<TUser> : IDisposable where TUser : class
    {
        /// <summary>
        /// 获取指定的<paramref name =“ user” />的用户标识符。
        /// </summary>
        /// <param name="user">The user whose identifier should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the identifier for the specified <paramref name="user"/>.</returns>
        Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 获取指定的<paramref name =“ user” />的用户名。
        /// </summary>
        /// <param name="user">The user whose name should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the name for the specified <paramref name="user"/>.</returns>
        Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 为指定的<paramref name =“ user” />设置给定的<paramref name =“ userName” />。
        /// </summary>
        /// <param name="user">The user whose name should be set.</param>
        /// <param name="userName">The user name to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken);

        /// <summary>
        /// 获取指定的<paramref name =“ user” />的规范化用户名。
        /// </summary>
        /// <param name="user">The user whose normalized name should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the normalized user name for the specified <paramref name="user"/>.</returns>
        Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 为指定的<paramref name =“ user” />设置给定的标准化名称。
        /// </summary>
        /// <param name="user">The user whose name should be set.</param>
        /// <param name="normalizedName">The normalized name to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken);

        /// <summary>
        /// 在用户存储中创建指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the creation operation.</returns>
        Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 更新用户存储中指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="user">The user to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 从用户存储中删除指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken);

        /// <summary>
        /// 查找并返回具有指定的<paramref name =“ userId” />的用户（如果有）。
        /// </summary>
        /// <param name="userId">The user ID to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
        /// </returns>
        Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken);

        /// <summary>
        /// 查找并返回具有指定规范化用户名的用户（如果有）。
        /// </summary>
        /// <param name="normalizedUserName">The normalized user name to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="normalizedUserName"/> if it exists.
        /// </returns>
        Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken);
    }
```
### IUserTwoFactorRecoveryCodeStore
```
    /// <summary>
    /// 为存储用户恢复代码的存储提供抽象。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserTwoFactorRecoveryCodeStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        /// 为用户更新恢复代码，同时使所有先前的恢复代码无效。
        /// </summary>
        /// <param name="user">The user to store new recovery codes for.</param>
        /// <param name="recoveryCodes">用户的新恢复代码.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The new recovery codes for the user.</returns>
        Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken);

        /// <summary>
        /// 返回恢复码对用户是否有效。 注意：恢复码仅有效
         ///一次，并希望在使用后被禁用。
        /// </summary>
        /// <param name="user">拥有恢复代码的用户.</param>
        /// <param name="code">The recovery code to use.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>True if the recovery code was found for the user.</returns>
        Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken);

        /// <summary>
        /// 返回多少个恢复代码对用户仍然有效。
        /// </summary>
        /// <param name="user">The user who owns the recovery code.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The number of valid recovery codes for the user..</returns>
        Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken);
    }
```
### IUserTwoFactorStore
```
    /// <summary>
    ///提供一个抽象存储标志，启用了两个因素身份验证。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserTwoFactorStore<TUser> : IUserStore<TUser> where TUser : class
    {
        /// <summary>
        ///设置一个标志，该标志指示指定的<paramref name =“ user” />是否启用了双重身份验证，
         ///作为异步操作。
        /// </summary>
        /// <param name="user">The user whose two factor authentication enabled status should be set.</param>
        /// <param name="enabled">A flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken);

        /// <summary>
        ///返回一个标志，指示指定的<paramref name =“ user” />是否启用了双重身份验证，
         ///作为异步操作。
        /// </summary>
        /// <param name="user">The user whose two factor authentication enabled status should be set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing a flag indicating whether the specified 
        /// <paramref name="user"/> has two factor authentication enabled or not.
        /// </returns>
        Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken);
    }
```
### IUserTwoFactorTokenProvider
```
    /// <summary>
    /// 提供两个因子令牌生成器的抽象。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserTwoFactorTokenProvider<TUser> where TUser : class
    {
        /// <summary>
        /// 为指定的<paramref name =“ user” />和<paramref name =“ purpose” />生成令牌。
        /// </summary>
        /// <param name="purpose">令牌的目的将用于</param>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> that can be used to retrieve user properties.</param>
        /// <param name="user">The user a token should be generated for.</param>
        /// <returns>
        /// <see cref =“ Task” />代表异步操作，其中包含指定的令牌
         /// <paramref name =“ user” />和<paramref name =“ purpose” />。
        /// </returns>
        /// <remarks>
        /// <paramref name =“ purpose” />参数允许令牌生成器用于多种令牌，而
         ///确保将令牌用于一种目的不能用于另一种目的。 例如，如果您指定了“电子邮件”的目的
         ///并以相同的目的对其进行了验证，以TOTP为目标的令牌将无法通过检查
         ///对于同一用户。
        ///
         /// <see cref =“ IUserTwoFactorTokenProvider {TUser}” />的实现应验证目的不为null或为空
         ///帮助令牌分离。
        /// </remarks>
        Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user);

        /// <summary>
        /// 返回一个标志，指示指定的<paramref name =“ token” />对给定有效
         /// <paramref name =“ user” />和<paramref name =“ purpose” />。
        /// </summary>
        /// <param name="purpose">令牌的目的将用于.</param>
        /// <param name="token">验证令牌.</param>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> that can be used to retrieve user properties.</param>
        /// <param name="user">The user a token should be validated for.</param>
        /// <returns>
        /// <see cref =“ Task” />代表异步操作，包含标记结果
         ///为指定的</ paramref>验证<paramref name =“ token”>。<paramref name =“ user” />和<paramref name =“ purpose” />。
         ///如果令牌有效，则任务希望返回true，否则返回false。
        /// </returns>
        Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user);

        /// <summary>
        /// 返回一个标志，指示提供者是否能够生成适用于以下方面的两因素身份验证令牌的令牌：
         ///指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> that can be used to retrieve user properties.</param>
        /// <param name="user">The user a token could be generated for.</param>
        /// <returns>
        /// <see cref =“ task” />代表异步操作，如果包含两个，则包含标志标志
         ///此提供者可以为指定的<paramref name =“ user” />生成因子标记。
         ///如果生成了两因素身份验证令牌，则任务希望返回true，否则返回false。
        /// </returns>
        Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user);
    }
```
### IUserValidator
```
    /// <summary>
    ///提供用于用户验证的抽象。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public interface IUserValidator<TUser> where TUser : class
    {
        /// <summary>
        /// 将指定的<paramref name =“ user” />验证为异步操作。
        /// </summary>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> that can be used to retrieve user properties.</param>
        /// <param name="user">The user to validate.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the validation operation.</returns>
        Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user);
    }
```
### AuthenticatorTokenProvider
```
    /// <summary>
    ///用于验证码验证。
    /// </summary>
    public class AuthenticatorTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser> where TUser : class
    {
        /// <summary>
        /// 检查是否为指定的<paramref name =“ user” />生成了两因素身份验证令牌。
        /// </summary>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> to retrieve the <paramref name="user"/> from.</param>
        /// <param name="user">The <typeparamref name="TUser"/> to check for the possibility of generating a two factor authentication token.</param>
        /// <returns>True if the user has an authenticator key set, otherwise false.</returns>
        public async virtual Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
        {
            var key = await manager.GetAuthenticatorKeyAsync(user);
            return !string.IsNullOrWhiteSpace(key);
        }

        /// <summary>
        /// 由于未发送验证码，因此返回空字符串。
        /// </summary>
        /// <param name="purpose">Ignored.</param>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> to retrieve the <paramref name="user"/> from.</param>
        /// <param name="user">The <typeparamref name="TUser"/>.</param>
        /// <returns>string.Empty.</returns>
        public virtual Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            return Task.FromResult(string.Empty);
        }

        /// <summary>
        /// 返回一个标志，指示指定的<paramref name =“ token” />对给定有效
         /// <paramref name =“ user” />和<paramref name =“ purpose” />。
        /// </summary>
        /// <param name="purpose"></param>
        /// <param name="token"></param>
        /// <param name="manager"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        public virtual async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
        {
            var key = await manager.GetAuthenticatorKeyAsync(user);
            int code;
            if (!int.TryParse(token, out code))
            {
                return false;
            }

            var hash = new HMACSHA1(Base32.FromBase32(key));
            var unixTimestamp = Convert.ToInt64(Math.Round((DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds));
            var timestep = Convert.ToInt64(unixTimestamp / 30);
            // Allow codes from 90s in each direction (we could make this configurable?)
            for (int i = -2; i <= 2; i++)
            {
                var expectedCode = Rfc6238AuthenticationService.ComputeTotp(hash, (ulong)(timestep + i), modifier: null);
                if (expectedCode == code)
                {
                    return true;
                }
            }
            return false;
        }
   }
```
### Base32
```
    internal static class Base32
    {
        private static readonly string _base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        public static string ToBase32(byte[] input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }

            StringBuilder sb = new StringBuilder();
            for (int offset = 0; offset < input.Length;)
            {
                byte a, b, c, d, e, f, g, h;
                int numCharsToOutput = GetNextGroup(input, ref offset, out a, out b, out c, out d, out e, out f, out g, out h);

                sb.Append((numCharsToOutput >= 1) ? _base32Chars[a] : '=');
                sb.Append((numCharsToOutput >= 2) ? _base32Chars[b] : '=');
                sb.Append((numCharsToOutput >= 3) ? _base32Chars[c] : '=');
                sb.Append((numCharsToOutput >= 4) ? _base32Chars[d] : '=');
                sb.Append((numCharsToOutput >= 5) ? _base32Chars[e] : '=');
                sb.Append((numCharsToOutput >= 6) ? _base32Chars[f] : '=');
                sb.Append((numCharsToOutput >= 7) ? _base32Chars[g] : '=');
                sb.Append((numCharsToOutput >= 8) ? _base32Chars[h] : '=');
            }

            return sb.ToString();
        }

        public static byte[] FromBase32(string input)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }
            input = input.TrimEnd('=').ToUpperInvariant();
            if (input.Length == 0)
            {
                return new byte[0];
            }

            var output = new byte[input.Length * 5 / 8];
            var bitIndex = 0;
            var inputIndex = 0;
            var outputBits = 0;
            var outputIndex = 0;
            while (outputIndex < output.Length)
            {
                var byteIndex = _base32Chars.IndexOf(input[inputIndex]);
                if (byteIndex < 0)
                {
                    throw new FormatException();
                }

                var bits = Math.Min(5 - bitIndex, 8 - outputBits);
                output[outputIndex] <<= bits;
                output[outputIndex] |= (byte)(byteIndex >> (5 - (bitIndex + bits)));

                bitIndex += bits;
                if (bitIndex >= 5)
                {
                    inputIndex++;
                    bitIndex = 0;
                }

                outputBits += bits;
                if (outputBits >= 8)
                {
                    outputIndex++;
                    outputBits = 0;
                }
            }
            return output;
        }

        // 返回输出的字节数
        private static int GetNextGroup(byte[] input, ref int offset, out byte a, out byte b, out byte c, out byte d, out byte e, out byte f, out byte g, out byte h)
        {
            uint b1, b2, b3, b4, b5;

            int retVal;
            switch (offset - input.Length)
            {
                case 1: retVal = 2; break;
                case 2: retVal = 4; break;
                case 3: retVal = 5; break;
                case 4: retVal = 7; break;
                default: retVal = 8; break;
            }

            b1 = (offset < input.Length) ? input[offset++] : 0U;
            b2 = (offset < input.Length) ? input[offset++] : 0U;
            b3 = (offset < input.Length) ? input[offset++] : 0U;
            b4 = (offset < input.Length) ? input[offset++] : 0U;
            b5 = (offset < input.Length) ? input[offset++] : 0U;

            a = (byte)(b1 >> 3);
            b = (byte)(((b1 & 0x07) << 2) | (b2 >> 6));
            c = (byte)((b2 >> 1) & 0x1f);
            d = (byte)(((b2 & 0x01) << 4) | (b3 >> 4));
            e = (byte)(((b3 & 0x0f) << 1) | (b4 >> 7));
            f = (byte)((b4 >> 2) & 0x1f);
            g = (byte)(((b4 & 0x3) << 3) | (b5 >> 5));
            h = (byte)(b5 & 0x1f);

            return retVal;
        }
    }
```
### ClaimsIdentityOptions
```
    /// <summary>
    /// 用于配置用于众所周知的声明的声明类型的选项。
    /// </summary>
    public class ClaimsIdentityOptions
    {
        /// <summary>
        /// 获取或设置用于角色声明的声明类型。 默认为<see cref =“ ClaimTypes.Role” />。
        /// </summary>
        public string RoleClaimType { get; set; } = ClaimTypes.Role;

        /// <summary>
        /// 获取或设置用于用户名声明的ClaimType。 默认为<see cref =“ ClaimTypes.Name” />。
        /// </summary>
        public string UserNameClaimType { get; set; } = ClaimTypes.Name;

        /// <summary>
        ///获取或设置用于用户标识符声明的ClaimType。 默认为<see cref =“ ClaimTypes.NameIdentifier” />。
        /// </summary>
        public string UserIdClaimType { get; set; } = ClaimTypes.NameIdentifier;

        /// <summary>
        /// Gets or sets the ClaimType used for the security stamp claim. Defaults to "AspNet.Identity.SecurityStamp".
        /// </summary>
        public string SecurityStampClaimType { get; set; } = "AspNet.Identity.SecurityStamp";
    }
```
### DefaultPersonalDataProtector
```
    /// <summary>
    /// <see cref =“ IPersonalDataProtector” />的默认实现，该实现使用<see cref =“ ILookupProtectorKeyRing” />
     ///和<see cref =“ ILookupProtector” />以保护有效载荷格式为{keyId}的数据：{protectedData}
    /// </summary>
    public class DefaultPersonalDataProtector : IPersonalDataProtector
    {
        private readonly ILookupProtectorKeyRing _keyRing;
        private readonly ILookupProtector _encryptor;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="keyRing"></param>
        /// <param name="protector"></param>
        public DefaultPersonalDataProtector(ILookupProtectorKeyRing keyRing, ILookupProtector protector)
        {
            _keyRing = keyRing;
            _encryptor = protector;
        }

        /// <summary>
        /// 取消保护数据。
        /// </summary>
        /// <param name="data">The data to unprotect.</param>
        /// <returns>The unprotected data.</returns>
        public virtual string Unprotect(string data)
        {
            var split = data.IndexOf(':');
            if (split == -1 || split == data.Length-1)
            {
                throw new InvalidOperationException("Malformed data.");
            }

            var keyId = data.Substring(0, split);
            return _encryptor.Unprotect(keyId, data.Substring(split + 1));
        }

        /// <summary>
        /// 保护数据。
        /// </summary>
        /// <param name="data">The data to protect.</param>
        /// <returns>The protected data.</returns>
        public virtual string Protect(string data)
        {
            var current = _keyRing.CurrentKeyId;
            return current + ":" + _encryptor.Protect(current, data);
        }
    }
```
### DefaultUserConfirmation
```
   /// <summary>
    /// <see cref =“ IUserConfirmation {TUser}” />的默认实现。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public class DefaultUserConfirmation<TUser> : IUserConfirmation<TUser> where TUser : class
    {
        /// <summary>
        /// 确定是否确认指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="manager"><see cref =“ UserManager {TUser}” /> />可用于检索用户属性。</param>
        /// <param name="user">The user.</param>
        /// <returns>The <see cref="Task"/> 代表异步操作，其中包含确认操作的<see cref =“ IdentityResult” />。</returns>
        public async virtual Task<bool> IsConfirmedAsync(UserManager<TUser> manager, TUser user)
        {
            if (!await manager.IsEmailConfirmedAsync(user))
            {
                return false;
            }
            return true;
        }
    }
```
### EmailTokenProvider
```
    /// <summary>
    /// TokenProvider从用户的安全性戳生成令牌并通过电子邮件通知用户。
    /// </summary>
    /// <typeparam name="TUser">The type used to represent a user.</typeparam>
    public class EmailTokenProvider<TUser> : TotpSecurityStampBasedTokenProvider<TUser>
        where TUser : class
    {
        /// <summary>
        /// 检查是否为指定的<paramref name =“ user” />生成了两因素身份验证令牌。
        /// </summary>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> to retrieve the <paramref name="user"/> from.</param>
        /// <param name="user">The <typeparamref name="TUser"/> to check for the possibility of generating a two factor authentication token.</param>
        /// <returns>True if the user has an email address set, otherwise false.</returns>
        public override async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
        {
            var email = await manager.GetEmailAsync(user);
            return !string.IsNullOrWhiteSpace(email) && await manager.IsEmailConfirmedAsync(user);
        }

        /// <summary>
        /// 返回一个值，供用户在生成的令牌中用作熵。
        /// </summary>
        /// <param name="purpose">The purpose of the two factor authentication token.</param>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> to retrieve the <paramref name="user"/> from.</param>
        /// <param name="user">The <typeparamref name="TUser"/> to check for the possibility of generating a two factor authentication token.</param>
        /// <returns>适合用作令牌生成中的熵的字符串.</returns>
        public override async Task<string> GetUserModifierAsync(string purpose, UserManager<TUser> manager,
            TUser user)
        {
            var email = await manager.GetEmailAsync(user);
            return "Email:" + purpose + ":" + email;
        }
    }
```
### IdentityBuilder
```
    /// <summary>
    /// 帮助程序功能，用于配置身份服务。
    /// </summary>
    public class IdentityBuilder
    {
        /// <summary>
        /// 创建<see cref =“ IdentityBuilder” />的新实例。
        /// </summary>
        /// <param name="user">The <see cref="Type"/> to use for the users.</param>
        /// <param name="services">The <see cref="IServiceCollection"/> to attach to.</param>
        public IdentityBuilder(Type user, IServiceCollection services)
        {
            UserType = user;
            Services = services;
        }

        /// <summary>
        /// Creates a new instance of <see cref="IdentityBuilder"/>.
        /// </summary>
        /// <param name="user">The <see cref="Type"/> to use for the users.</param>
        /// <param name="role">The <see cref="Type"/> to use for the roles.</param>
        /// <param name="services">The <see cref="IServiceCollection"/> to attach to.</param>
        public IdentityBuilder(Type user, Type role, IServiceCollection services) : this(user, services)
            => RoleType = role;

        /// <summary>
        ///获取用于用户的<see cref =“ Type” />。
        /// </summary>
        /// <value>
        /// The <see cref="Type"/> used for users.
        /// </value>
        public Type UserType { get; private set; }


        /// <summary>
        ///获取用于角色的<see cref =“ Type” />。
        /// </summary>
        /// <value>
        /// The <see cref="Type"/> used for roles.
        /// </value>
        public Type RoleType { get; private set; }

        /// <summary>
        ///获取连接到的<see cref =“ IServiceCollection” />服务。
        /// </summary>
        /// <value>
        /// The <see cref="IServiceCollection"/> services are attached to.
        /// </value>
        public IServiceCollection Services { get; private set; }

        private IdentityBuilder AddScoped(Type serviceType, Type concreteType)
        {
            Services.AddScoped(serviceType, concreteType);
            return this;
        }

        /// <summary>
        /// 将<see Also cref =“ UserType” />添加到<see cref =“ IUserValidator {TUser}”“ />。
        /// </summary>
        /// <typeparam name="TValidator">The user validator type.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddUserValidator<TValidator>() where TValidator : class
            => AddScoped(typeof(IUserValidator<>).MakeGenericType(UserType), typeof(TValidator));

        /// <summary>
        ///将<seealso cref =“ UserType” />添加到<see cref =“ IUserClaimsPrincipalFactory {TUser}”“ />中。
        /// </summary>
        /// <typeparam name="TFactory">The type of the claims principal factory.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddClaimsPrincipalFactory<TFactory>() where TFactory : class
            => AddScoped(typeof(IUserClaimsPrincipalFactory<>).MakeGenericType(UserType), typeof(TFactory));

        /// <summary>
        /// 添加到<see cref =“ IdentityErrorDescriber” />。
        /// </summary>
        /// <typeparam name="TDescriber">The type of the error describer.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddErrorDescriber<TDescriber>() where TDescriber : IdentityErrorDescriber
        {
            Services.AddScoped<IdentityErrorDescriber, TDescriber>();
            return this;
        }

        /// <summary>
        ///为<seealso cref =“ UserType” />添加到<see cref =“ IPasswordValidator {TUser}”“ />。
        /// </summary>
        /// <typeparam name="TValidator">The validator type used to validate passwords.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddPasswordValidator<TValidator>() where TValidator : class
            => AddScoped(typeof(IPasswordValidator<>).MakeGenericType(UserType), typeof(TValidator));

        /// <summary>
        /// Adds an <see cref="IUserStore{TUser}"/> for the <seealso cref="UserType"/>.
        /// </summary>
        /// <typeparam name="TStore">The user store type.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddUserStore<TStore>() where TStore : class
            => AddScoped(typeof(IUserStore<>).MakeGenericType(UserType), typeof(TStore));

        /// <summary>
        /// 添加令牌提供者。
        /// </summary>
        /// <typeparam name="TProvider">The type of the token provider to add.</typeparam>
        /// <param name="providerName">The name of the provider to add.</param>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddTokenProvider<TProvider>(string providerName) where TProvider : class
            => AddTokenProvider(providerName, typeof(TProvider));

        /// <summary>
        /// 为<seealso cref =“ UserType” />添加令牌提供者。
        /// </summary>
        /// <param name="providerName">要添加的提供者的名称.</param>
        /// <param name="provider">要添加的<see cref =“ IUserTwoFactorTokenProvider {TUser}” />的类型。</param>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddTokenProvider(string providerName, Type provider)
        {
            if (!typeof(IUserTwoFactorTokenProvider<>).MakeGenericType(UserType).GetTypeInfo().IsAssignableFrom(provider.GetTypeInfo()))
            {
                throw new InvalidOperationException(Resources.FormatInvalidManagerType(provider.Name, "IUserTwoFactorTokenProvider", UserType.Name));
            }
            Services.Configure<IdentityOptions>(options =>
            {
                options.Tokens.ProviderMap[providerName] = new TokenProviderDescriptor(provider);
            });
            Services.AddTransient(provider);
            return this; 
        }

        /// <summary>
        /// Adds a <see cref="UserManager{TUser}"/> for the <seealso cref="UserType"/>.
        /// </summary>
        /// <typeparam name="TUserManager">The type of the user manager to add.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddUserManager<TUserManager>() where TUserManager : class
        {
            var userManagerType = typeof(UserManager<>).MakeGenericType(UserType);
            var customType = typeof(TUserManager);
            if (!userManagerType.GetTypeInfo().IsAssignableFrom(customType.GetTypeInfo()))
            {
                throw new InvalidOperationException(Resources.FormatInvalidManagerType(customType.Name, "UserManager", UserType.Name));
            }
            if (userManagerType != customType)
            {
                Services.AddScoped(customType, services => services.GetRequiredService(userManagerType));
            }
            return AddScoped(userManagerType, customType);
        }

        /// <summary>
        /// 为TRole添加与角色相关的服务，包括IRoleStore，IRoleValidator和RoleManager。
        /// </summary>
        /// <typeparam name="TRole">The role type.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddRoles<TRole>() where TRole : class
        {
            RoleType = typeof(TRole);
            AddRoleValidator<RoleValidator<TRole>>();
            Services.TryAddScoped<RoleManager<TRole>>();
            Services.AddScoped(typeof(IUserClaimsPrincipalFactory<>).MakeGenericType(UserType), typeof(UserClaimsPrincipalFactory<,>).MakeGenericType(UserType, RoleType));
            return this;
        }

        /// <summary>
        /// Adds an <see cref="IRoleValidator{TRole}"/> for the <seealso cref="RoleType"/>.
        /// </summary>
        /// <typeparam name="TRole">The role validator type.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddRoleValidator<TRole>() where TRole : class
        {
            if (RoleType == null)
            {
                throw new InvalidOperationException(Resources.NoRoleType);
            }
            return AddScoped(typeof(IRoleValidator<>).MakeGenericType(RoleType), typeof(TRole));
        }

        /// <summary>
        /// Adds an <see cref="ILookupProtector"/> and <see cref="ILookupProtectorKeyRing"/>.
        /// </summary>
        /// <typeparam name="TProtector">个人数据保护器类型.</typeparam>
        /// <typeparam name="TKeyRing">个人数据保护器钥匙圈类型.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddPersonalDataProtection<TProtector, TKeyRing>() 
            where TProtector : class,ILookupProtector
            where TKeyRing : class, ILookupProtectorKeyRing
        {
            Services.AddSingleton<IPersonalDataProtector, DefaultPersonalDataProtector>();
            Services.AddSingleton<ILookupProtector, TProtector>();
            Services.AddSingleton<ILookupProtectorKeyRing, TKeyRing>();
            return this;
        }

        /// <summary>
        /// Adds a <see cref="IRoleStore{TRole}"/> for the <seealso cref="RoleType"/>.
        /// </summary>
        /// <typeparam name="TStore">The role store.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddRoleStore<TStore>() where TStore : class
        {
            if (RoleType == null)
            {
                throw new InvalidOperationException(Resources.NoRoleType);
            }
            return AddScoped(typeof(IRoleStore<>).MakeGenericType(RoleType), typeof(TStore));
        }

        /// <summary>
        /// Adds a <see cref="RoleManager{TRole}"/> for the <seealso cref="RoleType"/>.
        /// </summary>
        /// <typeparam name="TRoleManager">The type of the role manager to add.</typeparam>
        /// <returns>The current <see cref="IdentityBuilder"/> instance.</returns>
        public virtual IdentityBuilder AddRoleManager<TRoleManager>() where TRoleManager : class
        {
            if (RoleType == null)
            {
                throw new InvalidOperationException(Resources.NoRoleType);
            }
            var managerType = typeof(RoleManager<>).MakeGenericType(RoleType);
            var customType = typeof(TRoleManager);
            if (!managerType.GetTypeInfo().IsAssignableFrom(customType.GetTypeInfo()))
            {
                throw new InvalidOperationException(Resources.FormatInvalidManagerType(customType.Name, "RoleManager", RoleType.Name));
            }
            if (managerType != customType)
            {
                Services.AddScoped(typeof(TRoleManager), services => services.GetRequiredService(managerType));
            }
            return AddScoped(managerType, typeof(TRoleManager));
        }
    }
```
### IdentityError
```
    /// <summary>
    ///封装来自身份子系统的错误。
    /// </summary>
    public class IdentityError
    {
        /// <summary>
        /// Gets or sets the code for this error.
        /// </summary>
        /// <value>
        /// The code for this error.
        /// </value>
        public string Code { get; set; }

        /// <summary>
        /// Gets or sets the description for this error.
        /// </summary>
        /// <value>
        /// The description for this error.
        /// </value>
        public string Description { get; set; }
    }
```
### IdentityErrorDescriber
```
    /// <summary>
    /// 启用应用本地化的服务
    /// </summary>
    /// <remarks>
    /// 这些错误返回给最终用户，通常用作显示消息。
    /// </remarks>
    public class IdentityErrorDescriber
    {
        /// <summary>
        /// 返回默认值<see cref =“ IdentityError” />。...
        /// </summary>
        /// <returns>The default <see cref="IdentityError"/>.</returns>
        public virtual IdentityError DefaultError()
        {
            return new IdentityError
            {
                Code = nameof(DefaultError),
                Description = Resources.DefaultError
            };
        }

        /// <summary>
        /// 返回到<see cref =“ IdentityError” />，指示并发失败。
        /// </summary>
        /// <returns>An <see cref="IdentityError"/> indicating a concurrency failure.</returns>
        public virtual IdentityError ConcurrencyFailure()
        {
            return new IdentityError
            {
                Code = nameof(ConcurrencyFailure),
                Description = Resources.ConcurrencyFailure
            };
        }

        /// <summary>
        /// 返回到<see cref =“ IdentityError” />，指示密码不匹配。
        /// </summary>
        /// <returns>An <see cref="IdentityError"/> indicating a password mismatch.</returns>
        public virtual IdentityError PasswordMismatch()
        {
            return new IdentityError
            {
                Code = nameof(PasswordMismatch),
                Description = Resources.PasswordMismatch
            };
        }

        /// <summary>
        /// 返回到<see cref =“ IdentityError” />，指示无效的令牌。
        /// </summary>
        /// <returns>An <see cref="IdentityError"/> indicating an invalid token.</returns>
        public virtual IdentityError InvalidToken()
        {
            return new IdentityError
            {
                Code = nameof(InvalidToken),
                Description = Resources.InvalidToken
            };
        }

        /// <summary>
        /// 返回到<see cref =“ IdentityError” />，指示未兑换恢复码。
        /// </summary>
        /// <returns>An <see cref="IdentityError"/> indicating a recovery code was not redeemed.</returns>
        public virtual IdentityError RecoveryCodeRedemptionFailed()
        {
            return new IdentityError
            {
                Code = nameof(RecoveryCodeRedemptionFailed),
                Description = Resources.RecoveryCodeRedemptionFailed
            };
        }

        /// <summary>
        /// 返回到<see cref =“ IdentityError” />表示外部登录已经与一个帐户关联。
        /// </summary>
        /// <returns>An <see cref="IdentityError"/> indicating an external login is already associated with an account.</returns>
        public virtual IdentityError LoginAlreadyAssociated()
        {
            return new IdentityError
            {
                Code = nameof(LoginAlreadyAssociated),
                Description = Resources.LoginAlreadyAssociated
            };
        }

        /// <summary>
        /// 返回到<see cref =“ IdentityError” />，指示指定的用户<paramref name =“ userName” />无效。
        /// </summary>
        /// <param name="userName">The user name that is invalid.</param>
        /// <returns>An <see cref="IdentityError"/> indicating the specified user <paramref name="userName"/> is invalid.</returns>
        public virtual IdentityError InvalidUserName(string userName)
        {
            return new IdentityError
            {
                Code = nameof(InvalidUserName),
                Description = Resources.FormatInvalidUserName(userName)
            };
        }

        /// <summary>
        /// 返回到<see cref =“ IdentityError” />，指示指定的<paramref name =“ email” />无效。
        /// </summary>
        /// <param name="email">The email that is invalid.</param>
        /// <returns>An <see cref="IdentityError"/> indicating the specified <paramref name="email"/> is invalid.</returns>
        public virtual IdentityError InvalidEmail(string email)
        {
            return new IdentityError
            {
                Code = nameof(InvalidEmail),
                Description = Resources.FormatInvalidEmail(email)
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating the specified <paramref name="userName"/> already exists.
        /// </summary>
        /// <param name="userName">The user name that already exists.</param>
        /// <returns>An <see cref="IdentityError"/> indicating the specified <paramref name="userName"/> already exists.</returns>
        public virtual IdentityError DuplicateUserName(string userName)
        {
            return new IdentityError
            {
                Code = nameof(DuplicateUserName),
                Description = Resources.FormatDuplicateUserName(userName)
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating the specified <paramref name="email"/> is already associated with an account.
        /// </summary>
        /// <param name="email">The email that is already associated with an account.</param>
        /// <returns>An <see cref="IdentityError"/> indicating the specified <paramref name="email"/> is already associated with an account.</returns>
        public virtual IdentityError DuplicateEmail(string email)
        {
            return new IdentityError
            {
                Code = nameof(DuplicateEmail),
                Description = Resources.FormatDuplicateEmail(email)
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating the specified <paramref name="role"/> name is invalid.
        /// </summary>
        /// <param name="role">The invalid role.</param>
        /// <returns>An <see cref="IdentityError"/> indicating the specific role <paramref name="role"/> name is invalid.</returns>
        public virtual IdentityError InvalidRoleName(string role)
        {
            return new IdentityError
            {
                Code = nameof(InvalidRoleName),
                Description = Resources.FormatInvalidRoleName(role)
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating the specified <paramref name="role"/> name already exists.
        /// </summary>
        /// <param name="role">The duplicate role.</param>
        /// <returns>An <see cref="IdentityError"/> indicating the specific role <paramref name="role"/> name already exists.</returns>
        public virtual IdentityError DuplicateRoleName(string role)
        {
            return new IdentityError
            {
                Code = nameof(DuplicateRoleName),
                Description = Resources.FormatDuplicateRoleName(role)
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating a user already has a password.
        /// </summary>
        /// <returns>An <see cref="IdentityError"/> indicating a user already has a password.</returns>
        public virtual IdentityError UserAlreadyHasPassword()
        {
            return new IdentityError
            {
                Code = nameof(UserAlreadyHasPassword),
                Description = Resources.UserAlreadyHasPassword
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating user lockout is not enabled.
        /// </summary>
        /// <returns>An <see cref="IdentityError"/> indicating user lockout is not enabled.</returns>
        public virtual IdentityError UserLockoutNotEnabled()
        {
            return new IdentityError
            {
                Code = nameof(UserLockoutNotEnabled),
                Description = Resources.UserLockoutNotEnabled
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating a user is already in the specified <paramref name="role"/>.
        /// </summary>
        /// <param name="role">The duplicate role.</param>
        /// <returns>An <see cref="IdentityError"/> indicating a user is already in the specified <paramref name="role"/>.</returns>
        public virtual IdentityError UserAlreadyInRole(string role)
        {
            return new IdentityError
            {
                Code = nameof(UserAlreadyInRole),
                Description = Resources.FormatUserAlreadyInRole(role)
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating a user is not in the specified <paramref name="role"/>.
        /// </summary>
        /// <param name="role">The duplicate role.</param>
        /// <returns>An <see cref="IdentityError"/> indicating a user is not in the specified <paramref name="role"/>.</returns>
        public virtual IdentityError UserNotInRole(string role)
        {
            return new IdentityError
            {
                Code = nameof(UserNotInRole),
                Description = Resources.FormatUserNotInRole(role)
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating a password of the specified <paramref name="length"/> does not meet the minimum length requirements.
        /// </summary>
        /// <param name="length">The length that is not long enough.</param>
        /// <returns>An <see cref="IdentityError"/> indicating a password of the specified <paramref name="length"/> does not meet the minimum length requirements.</returns>
        public virtual IdentityError PasswordTooShort(int length)
        {
            return new IdentityError
            {
                Code = nameof(PasswordTooShort),
                Description = Resources.FormatPasswordTooShort(length)
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating a password does not meet the minimum number <paramref name="uniqueChars"/> of unique chars.
        /// </summary>
        /// <param name="uniqueChars">The number of different chars that must be used.</param>
        /// <returns>An <see cref="IdentityError"/> indicating a password does not meet the minimum number <paramref name="uniqueChars"/> of unique chars.</returns>
        public virtual IdentityError PasswordRequiresUniqueChars(int uniqueChars)
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresUniqueChars),
                Description = Resources.FormatPasswordRequiresUniqueChars(uniqueChars)
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating a password entered does not contain a non-alphanumeric character, which is required by the password policy.
        /// </summary>
        /// <returns>An <see cref="IdentityError"/> indicating a password entered does not contain a non-alphanumeric character.</returns>
        public virtual IdentityError PasswordRequiresNonAlphanumeric()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresNonAlphanumeric),
                Description = Resources.PasswordRequiresNonAlphanumeric
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating a password entered does not contain a numeric character, which is required by the password policy.
        /// </summary>
        /// <returns>An <see cref="IdentityError"/> indicating a password entered does not contain a numeric character.</returns>
        public virtual IdentityError PasswordRequiresDigit()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresDigit),
                Description = Resources.PasswordRequiresDigit
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating a password entered does not contain a lower case letter, which is required by the password policy.
        /// </summary>
        /// <returns>An <see cref="IdentityError"/> indicating a password entered does not contain a lower case letter.</returns>
        public virtual IdentityError PasswordRequiresLower()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresLower),
                Description = Resources.PasswordRequiresLower
            };
        }

        /// <summary>
        /// Returns an <see cref="IdentityError"/> indicating a password entered does not contain an upper case letter, which is required by the password policy.
        /// </summary>
        /// <returns>An <see cref="IdentityError"/> indicating a password entered does not contain an upper case letter.</returns>
        public virtual IdentityError PasswordRequiresUpper()
        {
            return new IdentityError
            {
                Code = nameof(PasswordRequiresUpper),
                Description = Resources.PasswordRequiresUpper
            };
        }
    }
```
### IdentityOptions
```
    /// <summary>
    /// 表示可用于配置身份系统的所有选项。
    /// </summary>
    public class IdentityOptions
    {
        /// <summary>
        /// 获取或设置身份系统的<see cref =“ ClaimsIdentityOptions” />。
        /// </summary>
        /// <value>
        /// The <see cref="ClaimsIdentityOptions"/> for the identity system.
        /// </value>
        public ClaimsIdentityOptions ClaimsIdentity { get; set; } = new ClaimsIdentityOptions();

        /// <summary>
        /// 获取或设置身份系统的<see cref =“ UserOptions” />。
        /// </summary>
        /// <value>
        /// The <see cref="UserOptions"/> for the identity system.
        /// </value>
        public UserOptions User { get; set; } = new UserOptions();

        /// <summary>
        /// 获取或设置身份系统的<see cref =“ PasswordOptions” />。
        /// </summary>
        /// <value>
        /// The <see cref="PasswordOptions"/> for the identity system.
        /// </value>
        public PasswordOptions Password { get; set; } = new PasswordOptions();

        /// <summary>
        /// 获取或设置身份系统的<see cref =“ LockoutOptions” />。
        /// </summary>
        /// <value>
        /// The <see cref="LockoutOptions"/> for the identity system.
        /// </value>
        public LockoutOptions Lockout { get; set; } = new LockoutOptions();

        /// <summary>
        ///获取或设置身份系统的<see cref =“ SignInOptions” />。
        /// </summary>
        /// <value>
        /// The <see cref="SignInOptions"/> for the identity system.
        /// </value>
        public SignInOptions SignIn { get; set; } = new SignInOptions();

        /// <summary>
        ///获取或设置身份系统的<see cref =“ TokenOptions” />。
        /// </summary>
        /// <value>
        /// The <see cref="TokenOptions"/> for the identity system.
        /// </value>
        public TokenOptions Tokens { get; set; } = new TokenOptions();

        /// <summary>
        /// 获取或设置身份系统的<see cref =“ StoreOptions” />。
        /// </summary>
        /// <value>
        /// The <see cref="StoreOptions"/> for the identity system.
        /// </value>
        public StoreOptions Stores { get; set; } = new StoreOptions();
    }
```
### IdentityResult
```
    /// <summary>
    /// 表示身份操作的结果。
    /// </summary>
    public class IdentityResult
    {
        private static readonly IdentityResult _success = new IdentityResult { Succeeded = true };
        private List<IdentityError> _errors = new List<IdentityError>();
        
        /// <summary>
        /// 指示操作是否成功的标志。
        /// </summary>
        /// <value>True if the operation succeeded, otherwise false.</value>
        public bool Succeeded { get; protected set; }

        /// <summary>
        ///一个<see cref =“ IEnumerable {T}” />的<see cref =“ IdentityError” />包含错误
         ///在身份操作期间发生。
        /// </summary>
        /// <value>An <see cref="IEnumerable{T}"/> of <see cref="IdentityError"/>s.</value>
        public IEnumerable<IdentityError> Errors => _errors;

        /// <summary>
        /// 返回到<see cref =“ IdentityResult” />，指示成功的身份操作。
        /// </summary>
        /// <returns>An <see cref="IdentityResult"/> indicating a successful operation.</returns>
        public static IdentityResult Success => _success;

        /// <summary>
        ///创建以<see cref =“ IdentityResult” />表示失败的身份操作，并带有<paramref name =“ errors” />的列表（如果适用）。
        /// </summary>
        /// <param name="errors">An optional array of <see cref="IdentityError"/>s which caused the operation to fail.</param>
        /// <returns>An <see cref="IdentityResult"/> indicating a failed identity operation, with a list of <paramref name="errors"/> if applicable.</returns>
        public static IdentityResult Failed(params IdentityError[] errors)
        {
            var result = new IdentityResult { Succeeded = false };
            if (errors != null)
            {
                result._errors.AddRange(errors);
            }
            return result;
        }

        /// <summary>
        /// 将当前<see cref =“ IdentityResult” />对象的值转换为其等效的字符串表示形式。
        /// </summary>
        /// <returns>A string representation of the current <see cref="IdentityResult"/> object.</returns>
        /// <remarks>
        /// If the operation was successful the ToString() will return "Succeeded" otherwise it returned 
        /// "Failed : " followed by a comma delimited list of error codes from its <see cref="Errors"/> collection, if any.
        /// </remarks>
        public override string ToString()
        {
            return Succeeded ? 
                   "Succeeded" : 
                   string.Format("{0} : {1}", "Failed", string.Join(",", Errors.Select(x => x.Code).ToList()));
        }
    }
```
### IdentityServiceCollectionExtensions
```
    /// <summary>
    ///包含用于配置身份服务的<see cref =“ IServiceCollection” />的扩展方法。
    /// </summary>
    public static class IdentityServiceCollectionExtensions
    {
        /// <summary>
        /// 为指定的用户类型添加和配置身份系统。 未添加角色服务
         ///默认情况下，但可以添加<见cref =“ IdentityBuilder.AddRoles {TRole}” />。
        /// </summary>
        /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
        /// <param name="services">The services available in the application.</param>
        /// <returns>An <see cref="IdentityBuilder"/> for creating and configuring the identity system.</returns>
        public static IdentityBuilder AddIdentityCore<TUser>(this IServiceCollection services) where TUser : class
            => services.AddIdentityCore<TUser>(o => { });

        /// <summary>
        /// 为指定的用户类型添加和配置身份系统。 默认情况下不添加角色服务
         ///，但可以添加<见cref =“ IdentityBuilder.AddRoles {TRole}” />。
        /// </summary>
        /// <typeparam name="TUser">The type representing a User in the system.</typeparam>
        /// <param name="services">The services available in the application.</param>
        /// <param name="setupAction">An action to configure the <see cref="IdentityOptions"/>.</param>
        /// <returns>An <see cref="IdentityBuilder"/> for creating and configuring the identity system.</returns>
        public static IdentityBuilder AddIdentityCore<TUser>(this IServiceCollection services, Action<IdentityOptions> setupAction)
            where TUser : class
        {
            // Services identity depends on
            services.AddOptions().AddLogging();

            // Services used by identity
            services.TryAddScoped<IUserValidator<TUser>, UserValidator<TUser>>();
            services.TryAddScoped<IPasswordValidator<TUser>, PasswordValidator<TUser>>();
            services.TryAddScoped<IPasswordHasher<TUser>, PasswordHasher<TUser>>();
            services.TryAddScoped<ILookupNormalizer, UpperInvariantLookupNormalizer>();
            services.TryAddScoped<IUserConfirmation<TUser>, DefaultUserConfirmation<TUser>>();
            // No interface for the error describer so we can add errors without rev'ing the interface
            services.TryAddScoped<IdentityErrorDescriber>();
            services.TryAddScoped<IUserClaimsPrincipalFactory<TUser>, UserClaimsPrincipalFactory<TUser>>();
            services.TryAddScoped<UserManager<TUser>>();

            if (setupAction != null)
            {
                services.Configure(setupAction);
            }

            return new IdentityBuilder(typeof(TUser), services);
        }
    }
```