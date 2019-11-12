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
* [LockoutOptions](#lockoutoptions)
* [PasswordHasher](#passwordhasher)
* [PasswordHasherCompatibilityMode](#passwordhashercompatibilitymode)
* [PasswordHasherOptions](#passwordhasheroptions)
* [PasswordOptions](#passwordoptions)
* [PasswordValidator](#passwordvalidator)
* [PasswordVerificationResult](#passwordverificationresult)
* [PersonalDataAttribute](#personaldataattribute)
* [PhoneNumberTokenProvider](#phonenumbertokenprovider)
* [PrincipalExtensions](#principalextensions)
* [ProtectedPersonalDataAttribute](#protectedpersonaldataattribute)
* [Rfc6238AuthenticationService](#rfc6238authenticationservice)
* [RoleManager](#rolemanager)
* [RoleValidator](#rolevalidator)
* [SignInOptions](#signinoptions)
* [SignInResult](#signinresult)
* [StoreOptions](#storeoptions)
* [TokenOptions](#tokenoptions)
* [TokenProviderDescriptor](#tokenproviderdescriptor)
* [TotpSecurityStampBasedTokenProvider](#totpsecuritystampBasedtokenprovider)
* [UpperInvariantLookupNormalizer](#upperinvariantlookupnormalizer)
* [UserClaimsPrincipalFactory](#userclaimsprincipalfactory)
* [UserLoginInfo](#userlogininfo)
* [UserManager](#usermanager)
* [UserOptions](#useroptions)
* [UserValidator](#uservalidator)
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
### LockoutOptions
```
    /// <summary>
    /// 用于配置用户锁定的选项。
    /// </summary>
    public class LockoutOptions
    {
        /// <summary>
        ///获取或设置一个标志 默认为true。
        /// </summary>
        /// <value>
        /// 如果可以锁定新创建的用户，则为true，否则为false。
        /// </value>
        public bool AllowedForNewUsers { get; set; } = true;

        /// <summary>
        /// 获取或设置用户被锁定之前允许的值，
         ///假设已启用锁定。 默认为5。
        /// </summary>
        /// <value>
        /// 如果启用了锁定，则在锁定用户之前允许的失败访问尝试次数。
        /// </value>
        public int MaxFailedAccessAttempts { get; set; } = 5;

        /// <summary>
        /// 获取或设置<see cref =“ TimeSpan” />，该用户因发生锁定而被锁定。 默认为5分钟。
        /// </summary>
        /// <value><see cref =“ TimeSpan” />用户被锁定以进行锁定</value>
        public TimeSpan DefaultLockoutTimeSpan { get; set; } = TimeSpan.FromMinutes(5);
    }
```
### PasswordHasher
```
    /// <summary>
    /// 实现标准的身份密码哈希。
    /// </summary>
    /// <typeparam name="TUser">用于表示用户的类型。</typeparam>
    public class PasswordHasher<TUser> : IPasswordHasher<TUser> where TUser : class
    {
        /* =======================
         * HASHED PASSWORD FORMATS
         * =======================
         * 
         * Version 2:
         * PBKDF2 with HMAC-SHA1, 128-bit salt, 256-bit subkey, 1000 iterations.
         * (See also: SDL crypto guidelines v5.1, Part III)
         * Format: { 0x00, salt, subkey }
         *
         * Version 3:
         * PBKDF2 with HMAC-SHA256, 128-bit salt, 256-bit subkey, 10000 iterations.
         * Format: { 0x01, prf (UInt32), iter count (UInt32), salt length (UInt32), salt, subkey }
         * (All UInt32s are stored big-endian.)
         */

        private readonly PasswordHasherCompatibilityMode _compatibilityMode;
        private readonly int _iterCount;
        private readonly RandomNumberGenerator _rng;

        /// <summary>
        /// 创建<see cref =“ PasswordHasher {TUser}” />的新实例。
        /// </summary>
        /// <param name="optionsAccessor">该实例的选项.</param>
        public PasswordHasher(IOptions<PasswordHasherOptions> optionsAccessor = null)
        {
            var options = optionsAccessor?.Value ?? new PasswordHasherOptions();

            _compatibilityMode = options.CompatibilityMode;
            switch (_compatibilityMode)
            {
                case PasswordHasherCompatibilityMode.IdentityV2:
                    // nothing else to do
                    break;

                case PasswordHasherCompatibilityMode.IdentityV3:
                    _iterCount = options.IterationCount;
                    if (_iterCount < 1)
                    {
                        throw new InvalidOperationException(Resources.InvalidPasswordHasherIterationCount);
                    }
                    break;

                default:
                    throw new InvalidOperationException(Resources.InvalidPasswordHasherCompatibilityMode);
            }

            _rng = options.Rng;
        }

#if NETSTANDARD2_0
        // 比较两个字节数组是否相等。 该方法是专门编写的，因此不会优化循环。
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null && b == null)
            {
                return true;
            }
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }
            var areSame = true;
            for (var i = 0; i < a.Length; i++)
            {
                areSame &= (a[i] == b[i]);
            }
            return areSame;
        }
#endif

        /// <summary>
        ///为指定的<paramref name =“ user” />返回提供的<paramref name =“ password” />的哈希表示。
        /// </summary>
        /// <param name="user">密码将被散列。</param>
        /// <param name="password">哈希密码.</param>
        /// <returns>所提供的哈希表示<paramref name="password"/> for the specified <paramref name="user"/>.</returns>
        public virtual string HashPassword(TUser user, string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            if (_compatibilityMode == PasswordHasherCompatibilityMode.IdentityV2)
            {
                return Convert.ToBase64String(HashPasswordV2(password, _rng));
            }
            else
            {
                return Convert.ToBase64String(HashPasswordV3(password, _rng));
            }
        }

        private static byte[] HashPasswordV2(string password, RandomNumberGenerator rng)
        {
            const KeyDerivationPrf Pbkdf2Prf = KeyDerivationPrf.HMACSHA1; // default for Rfc2898DeriveBytes
            const int Pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
            const int Pbkdf2SubkeyLength = 256 / 8; // 256 bits
            const int SaltSize = 128 / 8; // 128 bits

            // Produce a version 2 (see comment above) text hash.
            byte[] salt = new byte[SaltSize];
            rng.GetBytes(salt);
            byte[] subkey = KeyDerivation.Pbkdf2(password, salt, Pbkdf2Prf, Pbkdf2IterCount, Pbkdf2SubkeyLength);

            var outputBytes = new byte[1 + SaltSize + Pbkdf2SubkeyLength];
            outputBytes[0] = 0x00; // format marker
            Buffer.BlockCopy(salt, 0, outputBytes, 1, SaltSize);
            Buffer.BlockCopy(subkey, 0, outputBytes, 1 + SaltSize, Pbkdf2SubkeyLength);
            return outputBytes;
        }

        private byte[] HashPasswordV3(string password, RandomNumberGenerator rng)
        {
            return HashPasswordV3(password, rng,
                prf: KeyDerivationPrf.HMACSHA256,
                iterCount: _iterCount,
                saltSize: 128 / 8,
                numBytesRequested: 256 / 8);
        }

        private static byte[] HashPasswordV3(string password, RandomNumberGenerator rng, KeyDerivationPrf prf, int iterCount, int saltSize, int numBytesRequested)
        {
            // Produce a version 3 (see comment above) text hash.
            byte[] salt = new byte[saltSize];
            rng.GetBytes(salt);
            byte[] subkey = KeyDerivation.Pbkdf2(password, salt, prf, iterCount, numBytesRequested);

            var outputBytes = new byte[13 + salt.Length + subkey.Length];
            outputBytes[0] = 0x01; // format marker
            WriteNetworkByteOrder(outputBytes, 1, (uint)prf);
            WriteNetworkByteOrder(outputBytes, 5, (uint)iterCount);
            WriteNetworkByteOrder(outputBytes, 9, (uint)saltSize);
            Buffer.BlockCopy(salt, 0, outputBytes, 13, salt.Length);
            Buffer.BlockCopy(subkey, 0, outputBytes, 13 + saltSize, subkey.Length);
            return outputBytes;
        }

        private static uint ReadNetworkByteOrder(byte[] buffer, int offset)
        {
            return ((uint)(buffer[offset + 0]) << 24)
                | ((uint)(buffer[offset + 1]) << 16)
                | ((uint)(buffer[offset + 2]) << 8)
                | ((uint)(buffer[offset + 3]));
        }

        /// <summary>
        /// 返回一个<see cref =“ PasswordVerificationResult” />，它显示密码哈希比较的结果。
        /// </summary>
        /// <param name="user">应验证其密码的用户。</param>
        /// <param name="hashedPassword">用户存储的密码的哈希值.</param>
        /// <param name="providedPassword">提供的密码用于比较.</param>
        /// <returns>A <see cref="PasswordVerificationResult"/> 指示密码哈希的结果。</returns>
        /// <remarks>此方法的实现应保持一致。</remarks>
        public virtual PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
        {
            if (hashedPassword == null)
            {
                throw new ArgumentNullException(nameof(hashedPassword));
            }
            if (providedPassword == null)
            {
                throw new ArgumentNullException(nameof(providedPassword));
            }

            byte[] decodedHashedPassword = Convert.FromBase64String(hashedPassword);

            // read the format marker from the hashed password
            if (decodedHashedPassword.Length == 0)
            {
                return PasswordVerificationResult.Failed;
            }
            switch (decodedHashedPassword[0])
            {
                case 0x00:
                    if (VerifyHashedPasswordV2(decodedHashedPassword, providedPassword))
                    {
                        // This is an old password hash format - the caller needs to rehash if we're not running in an older compat mode.
                        return (_compatibilityMode == PasswordHasherCompatibilityMode.IdentityV3)
                            ? PasswordVerificationResult.SuccessRehashNeeded
                            : PasswordVerificationResult.Success;
                    }
                    else
                    {
                        return PasswordVerificationResult.Failed;
                    }

                case 0x01:
                    int embeddedIterCount;
                    if (VerifyHashedPasswordV3(decodedHashedPassword, providedPassword, out embeddedIterCount))
                    {
                        // If this hasher was configured with a higher iteration count, change the entry now.
                        return (embeddedIterCount < _iterCount)
                            ? PasswordVerificationResult.SuccessRehashNeeded
                            : PasswordVerificationResult.Success;
                    }
                    else
                    {
                        return PasswordVerificationResult.Failed;
                    }

                default:
                    return PasswordVerificationResult.Failed; // unknown format marker
            }
        }

        private static bool VerifyHashedPasswordV2(byte[] hashedPassword, string password)
        {
            const KeyDerivationPrf Pbkdf2Prf = KeyDerivationPrf.HMACSHA1; // default for Rfc2898DeriveBytes
            const int Pbkdf2IterCount = 1000; // default for Rfc2898DeriveBytes
            const int Pbkdf2SubkeyLength = 256 / 8; // 256 bits
            const int SaltSize = 128 / 8; // 128 bits

            // We know ahead of time the exact length of a valid hashed password payload.
            if (hashedPassword.Length != 1 + SaltSize + Pbkdf2SubkeyLength)
            {
                return false; // bad size
            }

            byte[] salt = new byte[SaltSize];
            Buffer.BlockCopy(hashedPassword, 1, salt, 0, salt.Length);

            byte[] expectedSubkey = new byte[Pbkdf2SubkeyLength];
            Buffer.BlockCopy(hashedPassword, 1 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

            // Hash the incoming password and verify it
            byte[] actualSubkey = KeyDerivation.Pbkdf2(password, salt, Pbkdf2Prf, Pbkdf2IterCount, Pbkdf2SubkeyLength);
#if NETSTANDARD2_0
            return ByteArraysEqual(actualSubkey, expectedSubkey);
#elif NETCOREAPP3_0
            return CryptographicOperations.FixedTimeEquals(actualSubkey, expectedSubkey);
#else
#error Update target frameworks
#endif
        }

        private static bool VerifyHashedPasswordV3(byte[] hashedPassword, string password, out int iterCount)
        {
            iterCount = default(int);

            try
            {
                // Read header information
                KeyDerivationPrf prf = (KeyDerivationPrf)ReadNetworkByteOrder(hashedPassword, 1);
                iterCount = (int)ReadNetworkByteOrder(hashedPassword, 5);
                int saltLength = (int)ReadNetworkByteOrder(hashedPassword, 9);

                // Read the salt: must be >= 128 bits
                if (saltLength < 128 / 8)
                {
                    return false;
                }
                byte[] salt = new byte[saltLength];
                Buffer.BlockCopy(hashedPassword, 13, salt, 0, salt.Length);

                // Read the subkey (the rest of the payload): must be >= 128 bits
                int subkeyLength = hashedPassword.Length - 13 - salt.Length;
                if (subkeyLength < 128 / 8)
                {
                    return false;
                }
                byte[] expectedSubkey = new byte[subkeyLength];
                Buffer.BlockCopy(hashedPassword, 13 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

                // Hash the incoming password and verify it
                byte[] actualSubkey = KeyDerivation.Pbkdf2(password, salt, prf, iterCount, subkeyLength);
#if NETSTANDARD2_0
                return ByteArraysEqual(actualSubkey, expectedSubkey);
#elif NETCOREAPP3_0
                return CryptographicOperations.FixedTimeEquals(actualSubkey, expectedSubkey);
#else
#error Update target frameworks
#endif
            }
            catch
            {
                // This should never occur except in the case of a malformed payload, where
                // we might go off the end of the array. Regardless, a malformed payload
                // implies verification failed.
                return false;
            }
        }

        private static void WriteNetworkByteOrder(byte[] buffer, int offset, uint value)
        {
            buffer[offset + 0] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)(value >> 0);
        }
    }
```
### PasswordHasherCompatibilityMode
```
    /// <summary>
    /// 指定用于哈希密码的格式。
    /// </summary>
    public enum PasswordHasherCompatibilityMode
    {
        /// <summary>
        /// 以与ASP.NET Identity版本1和2兼容的方式指示哈希密码。
        /// </summary>
        IdentityV2,

        /// <summary>
        /// 以与ASP.NET Identity版本3兼容的方式指示哈希密码。
        /// </summary>
        IdentityV3
    }
```
### PasswordHasherOptions
```
    /// <summary>
    /// 指定密码哈希的选项。
    /// </summary>
    public class PasswordHasherOptions
    {
        private static readonly RandomNumberGenerator _defaultRng = RandomNumberGenerator.Create(); // secure PRNG

        /// <summary>
        /// 获取或设置哈希密码时使用的兼容性。 默认为“ ASP.NET身份版本3”。
        /// </summary>
        /// <value>
        /// 使用的兼容模式具有哈希密码。
        /// </value>
        public PasswordHasherCompatibilityMode CompatibilityMode { get; set; } = PasswordHasherCompatibilityMode.IdentityV3;

        /// <summary>
        /// 获取或设置使用PBKDF2哈希密码时使用的迭代次数。 默认值为10,000。
        /// </summary>
        /// <value>
        /// 使用PBKDF2对密码进行哈希处理时使用的迭代次数。
        /// </value>
        /// <remarks>
        /// 仅当兼容模式设置为“ V3”时才使用此值。
         ///该值必须为正整数。
        /// </remarks>
        public int IterationCount { get; set; } = 10000;

        // for unit testing
        internal RandomNumberGenerator Rng { get; set; } = _defaultRng;
    }
```
###  PasswordOptions
```
    /// <summary>
    /// 指定密码要求的选项。
    /// </summary>
    public class PasswordOptions
    {
        /// <summary>
        /// 获取或设置密码必须的最小长度。 默认为6。
        /// </summary>
        public int RequiredLength { get; set; } = 6;

        /// <summary>
        ///获取或设置最小数量的唯一字符。 默认为1。
        /// </summary>
        public int RequiredUniqueChars { get; set; } = 1;

        /// <summary>
        /// 如果密码必须包含非字母数字字符，则获取或设置一个标志。 默认为true。
        /// </summary>
        /// <value>如果密码必须包含非字母数字字符，则为true，否则为false.</value>
        public bool RequireNonAlphanumeric { get; set; } = true;

        /// <summary>
        /// 获取或设置标志ASCII字符。 默认为true。
        /// </summary>
        /// <value>如果密码必须包含小写ASCII字符，则为True.</value>
        public bool RequireLowercase { get; set; } = true;

        /// <summary>
        /// 获取或设置标志ASCII字符。 默认为true。
        /// </summary>
        /// <value>如果密码必须包含大写ASCII字符，则为True.</value>
        public bool RequireUppercase { get; set; } = true;

        /// <summary>
        /// 获取或设置一个标志。 默认为true。
        /// </summary>
        /// <value>如果密码必须包含数字，则为真.</value>
        public bool RequireDigit { get; set; } = true;
    }
```
### PasswordValidator
```
    /// <summary>
    /// 提供身份的默认密码策略。
    /// </summary>
    /// <typeparam name="TUser">代表用户的类型.</typeparam>
    public class PasswordValidator<TUser> : IPasswordValidator<TUser> where TUser : class
    {
        /// <summary>
        /// 构造<see cref =“ PasswordValidator {TUser}” />的新实例。
        /// </summary>
        /// <param name="errors"><请参阅cref =“ IdentityErrorDescriber” />以从中检索错误文本.</param>
        public PasswordValidator(IdentityErrorDescriber errors = null)
        {
            Describer = errors ?? new IdentityErrorDescriber();
        }

        /// <summary>
        /// 获取用于提供错误文本的<see cref =“ IdentityErrorDescriber” />。
        /// </summary>
        /// <value>The <see cref="IdentityErrorDescriber"/> used to supply error text.</value>
        public IdentityErrorDescriber Describer { get; private set; }

        /// <summary>
        /// 验证有关异步操作的密码。
        /// </summary>
        /// <param name="manager"><see cref =“ UserManager {TUser}” />从<paramref name =“ user” />属性中检索.</param>
        /// <param name="user">应验证其密码的用户.</param>
        /// <param name="password">提供的验证密码</param>
        /// <returns>代表异步操作的任务对象。</returns>
        public virtual Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }
            var errors = new List<IdentityError>();
            var options = manager.Options.Password;
            if (string.IsNullOrWhiteSpace(password) || password.Length < options.RequiredLength)
            {
                errors.Add(Describer.PasswordTooShort(options.RequiredLength));
            }
            if (options.RequireNonAlphanumeric && password.All(IsLetterOrDigit))
            {
                errors.Add(Describer.PasswordRequiresNonAlphanumeric());
            }
            if (options.RequireDigit && !password.Any(IsDigit))
            {
                errors.Add(Describer.PasswordRequiresDigit());
            }
            if (options.RequireLowercase && !password.Any(IsLower))
            {
                errors.Add(Describer.PasswordRequiresLower());
            }
            if (options.RequireUppercase && !password.Any(IsUpper))
            {
                errors.Add(Describer.PasswordRequiresUpper());
            }
            if (options.RequiredUniqueChars >= 1 && password.Distinct().Count() < options.RequiredUniqueChars)
            {
                errors.Add(Describer.PasswordRequiresUniqueChars(options.RequiredUniqueChars));
            }
            return
                Task.FromResult(errors.Count == 0
                    ? IdentityResult.Success
                    : IdentityResult.Failed(errors.ToArray()));
        }

        /// <summary>
        /// 返回一个标志，指示提供的字符是否为数字。
        /// </summary>
        /// <param name="c">要检查的字符是否为数字.</param>
        /// <returns>如果字符是数字，则为true，否则为false.</returns>
        public virtual bool IsDigit(char c)
        {
            return c >= '0' && c <= '9';
        }

        /// <summary>
        /// 返回一个标志，指示提供的字符是否为小写ASCII字母。
        /// </summary>
        /// <param name="c">The character to check if it is a lower case ASCII letter.</param>
        /// <returns>True if the character is a lower case ASCII letter, otherwise false.</returns>
        public virtual bool IsLower(char c)
        {
            return c >= 'a' && c <= 'z';
        }

        /// <summary>
        /// 返回一个标志，指示提供的字符是否为大写ASCII字母。
        /// </summary>
        /// <param name="c">The character to check if it is an upper case ASCII letter.</param>
        /// <returns>True if the character is an upper case ASCII letter, otherwise false.</returns>
        public virtual bool IsUpper(char c)
        {
            return c >= 'A' && c <= 'Z';
        }

        /// <summary>
        ///返回一个标志，指示提供的字符是ASCII字母还是数字。
        /// </summary>
        /// <param name="c">The character to check if it is an ASCII letter or digit.</param>
        /// <returns>True if the character is an ASCII letter or digit, otherwise false.</returns>
        public virtual bool IsLetterOrDigit(char c)
        {
            return IsUpper(c) || IsLower(c) || IsDigit(c);
        }
    }
```
### PasswordVerificationResult
```
    /// <summary>
    /// 指定密码验证的结果。
    /// </summary>
    public enum PasswordVerificationResult
    {
        /// <summary>
        /// 表示密码验证失败。
        /// </summary>
        Failed = 0,

        /// <summary>
        /// 表示密码验证成功。
        /// </summary>
        Success = 1,

        /// <summary>
        /// 表示密码验证成功，但是使用不赞成使用的算法对密码进行了编码
         ///，并且应该重新定义和更新。
        /// </summary>
        SuccessRehashNeeded = 2
    }
```
### PersonalDataAttribute
```
    /// <summary>
    /// 用于表示已考虑某事。
    /// </summary>
    public class PersonalDataAttribute : Attribute
    { }
```
### PhoneNumberTokenProvider
```
    /// <summary>
    /// 表示一个令牌提供者，该提供者从用户的安全戳生成令牌，并且
     ///通过他们的电话号码将其发送给用户。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public class PhoneNumberTokenProvider<TUser> : TotpSecurityStampBasedTokenProvider<TUser>
        where TUser : class
    {
        /// <summary>
        /// 返回一个标志，指示提供者是否能够生成适用于以下方面的两因素身份验证令牌的令牌：
         ///指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> that can be used to retrieve user properties.</param>
        /// <param name="user">The user a token could be generated for.</param>
        /// <returns>
        /// <see cref =“ task” />代表异步操作，如果包含两个，则包含标志标志
         ///此提供者可以为指定的<paramref name =“ user” />生成因子标记。
         ///如果用户已经生成了两因素身份验证令牌，则任务希望返回true
         ///一个电话号码，否则为false。
        /// </returns>
        public override async Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }
            var phoneNumber = await manager.GetPhoneNumberAsync(user);
            return !string.IsNullOrWhiteSpace(phoneNumber) && await manager.IsPhoneNumberConfirmedAsync(user);
        }

        /// <summary>
        ///返回一个常量，提供者和用户唯一的修饰符，用于根据用户信息生成的令牌中的熵。
        /// </summary>
        /// <param name="purpose">The purpose the token will be generated for.</param>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> that can be used to retrieve user properties.</param>
        /// <param name="user">The user a token should be generated for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing a constant modifier for the specified 
        /// <paramref name="user"/> and <paramref name="purpose"/>.
        /// </returns>
        public override async Task<string> GetUserModifierAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }
            var phoneNumber = await manager.GetPhoneNumberAsync(user);
            return "PhoneNumber:" + purpose + ":" + phoneNumber;
        }
    }
```
### PrincipalExtensions
```
    /// <summary>
    ///与<see cref =“ ClaimsPrincipal” />的声明相关的扩展。
    /// </summary>
    public static class PrincipalExtensions
    {
        /// <summary>
        /// 返回指定类型的第一个声明的值，否则声明不存在。
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/> instance this method extends.</param>
        /// <param name="claimType">The claim type whose first value should be returned.</param>
        /// <returns>The value of the first instance of the specified claim type, or null if the claim is not present.</returns>
        public static string FindFirstValue(this ClaimsPrincipal principal, string claimType)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }
            var claim = principal.FindFirst(claimType);
            return claim != null ? claim.Value : null;
        }

    }
```
### ProtectedPersonalDataAttribute
```
    /// <summary>
    /// 用于表明它是个人数据，应受到保护。
    /// </summary>
    public class ProtectedPersonalDataAttribute : PersonalDataAttribute
    { }
```
### Rfc6238AuthenticationService
```
    internal static class Rfc6238AuthenticationService
    {
        private static readonly DateTime _unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private static readonly TimeSpan _timestep = TimeSpan.FromMinutes(3);
        private static readonly Encoding _encoding = new UTF8Encoding(false, true);
        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        // 生成一个新的80位安全令牌
        public static byte[] GenerateRandomKey()
        {
            byte[] bytes = new byte[20];
            _rng.GetBytes(bytes);
            return bytes;
        }

        internal static int ComputeTotp(HashAlgorithm hashAlgorithm, ulong timestepNumber, string modifier)
        {
            // # of 0's = length of pin
            const int Mod = 1000000;

            // See https://tools.ietf.org/html/rfc4226
            // We can add an optional modifier
            var timestepAsBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((long)timestepNumber));
            var hash = hashAlgorithm.ComputeHash(ApplyModifier(timestepAsBytes, modifier));

            // Generate DT string
            var offset = hash[hash.Length - 1] & 0xf;
            Debug.Assert(offset + 4 < hash.Length);
            var binaryCode = (hash[offset] & 0x7f) << 24
                             | (hash[offset + 1] & 0xff) << 16
                             | (hash[offset + 2] & 0xff) << 8
                             | (hash[offset + 3] & 0xff);

            return binaryCode % Mod;
        }

        private static byte[] ApplyModifier(byte[] input, string modifier)
        {
            if (String.IsNullOrEmpty(modifier))
            {
                return input;
            }

            var modifierBytes = _encoding.GetBytes(modifier);
            var combined = new byte[checked(input.Length + modifierBytes.Length)];
            Buffer.BlockCopy(input, 0, combined, 0, input.Length);
            Buffer.BlockCopy(modifierBytes, 0, combined, input.Length, modifierBytes.Length);
            return combined;
        }

        // More info: https://tools.ietf.org/html/rfc6238#section-4
        private static ulong GetCurrentTimeStepNumber()
        {
            var delta = DateTime.UtcNow - _unixEpoch;
            return (ulong)(delta.Ticks / _timestep.Ticks);
        }

        public static int GenerateCode(byte[] securityToken, string modifier = null)
        {
            if (securityToken == null)
            {
                throw new ArgumentNullException(nameof(securityToken));
            }

            // Allow a variance of no greater than 9 minutes in either direction
            var currentTimeStep = GetCurrentTimeStepNumber();
            using (var hashAlgorithm = new HMACSHA1(securityToken))
            {
                return ComputeTotp(hashAlgorithm, currentTimeStep, modifier);
            }
        }

        public static bool ValidateCode(byte[] securityToken, int code, string modifier = null)
        {
            if (securityToken == null)
            {
                throw new ArgumentNullException(nameof(securityToken));
            }

            // Allow a variance of no greater than 9 minutes in either direction
            var currentTimeStep = GetCurrentTimeStepNumber();
            using (var hashAlgorithm = new HMACSHA1(securityToken))
            {
                for (var i = -2; i <= 2; i++)
                {
                    var computedTotp = ComputeTotp(hashAlgorithm, (ulong)((long)currentTimeStep + i), modifier);
                    if (computedTotp == code)
                    {
                        return true;
                    }
                }
            }

            // No match
            return false;
        }
    }
```
### RoleManager
```
    /// <summary>
    /// 提供用于管理持久性存储中的角色的API。
    /// </summary>
    /// <typeparam name="TRole">The type encapsulating a role.</typeparam>
    public class RoleManager<TRole> : IDisposable where TRole : class
    {
        private bool _disposed;

        /// <summary>
        /// 用于取消操作的取消令牌。
        /// </summary>
        protected virtual CancellationToken CancellationToken => CancellationToken.None;

        /// <summary>
        /// Constructs a new instance of <see cref="RoleManager{TRole}"/>.
        /// </summary>
        /// <param name="store">管理想要操作的持久性存储.</param>
        /// <param name="roleValidators">角色验证者的集合.</param>
        /// <param name="keyNormalizer">将角色名称标准化为键时使用的标准化器.</param>
        /// <param name="errors"><see cref =“ IdentityErrorDescriber” />用于提供错误消息.</param>
        /// <param name="logger">The logger used to log messages, warnings and errors.</param>
        public RoleManager(IRoleStore<TRole> store,
            IEnumerable<IRoleValidator<TRole>> roleValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            ILogger<RoleManager<TRole>> logger)
        {
            if (store == null)
            {
                throw new ArgumentNullException(nameof(store));
            }
            Store = store;
            KeyNormalizer = keyNormalizer;
            ErrorDescriber = errors;
            Logger = logger;

            if (roleValidators != null)
            {
                foreach (var v in roleValidators)
                {
                    RoleValidators.Add(v);
                }
            }
        }

        /// <summary>
        /// 获取此实例进行操作的持久性存储。
        /// </summary>
        /// <value>此实例在其上运行的持久性存储.</value>
        protected IRoleStore<TRole> Store { get; private set; }

        /// <summary>
        /// 获取<see cref =“ ILogger” />，该日志用于记录来自管理器的消息。
        /// </summary>
        /// <value>
        /// The <see cref="ILogger"/> used to log messages from the manager.
        /// </value>
        public virtual ILogger Logger { get; set; }

        /// <summary>
        ///获取持久性之前要调用的角色的验证器列表。
        /// </summary>
        /// <value>持久性之前要调用的角色的验证器列表。</value>
        public IList<IRoleValidator<TRole>> RoleValidators { get; } = new List<IRoleValidator<TRole>>();

        /// <summary>
        /// 获取用于提供程序错误消息的<see cref =“ IdentityErrorDescriber” />。
        /// </summary>
        /// <value>
        /// <see cref =“ IdentityErrorDescriber” />用于提供错误消息。
        /// </value>
        public IdentityErrorDescriber ErrorDescriber { get; set; }

        /// <summary>
        /// 获取将角色名称标准化为键时要使用的标准化器。
        /// </summary>
        /// <value>
        /// 将角色名称标准化为键时使用的标准化器。
        /// </value>
        public ILookupNormalizer KeyNormalizer { get; set; }

        /// <summary>
        /// 如果持久性存储位于<see cref =“ IQueryableRoleStore {TRole}” />上，则获取角色的IQueryable集合，
         ///否则抛出<see cref =“ NotSupportedException” />。
        /// </summary>
        /// <value>如果持久性存储为<see cref =“ IQueryableRoleStore {TRole}” />，则为角色的IQueryable集合.</value>
        /// <exception cref="NotSupportedException">Thrown if the persistence store is not an <see cref="IQueryableRoleStore{TRole}"/>.</exception>
        /// <remarks>
        /// 此属性的调用者应使用<see cref =“ SupportsQueryableRoles” />来确保支持角色存储支持
         ///返回角色的IQueryable列表。
        /// </remarks>
        public virtual IQueryable<TRole> Roles
        {
            get
            {
                var queryableStore = Store as IQueryableRoleStore<TRole>;
                if (queryableStore == null)
                {
                    throw new NotSupportedException(Resources.StoreNotIQueryableRoleStore);
                }
                return queryableStore.Roles;
            }
        }

        /// <summary>
        /// 获取一个标志，该标志是支持返回到<see cref =“ IQueryable” />角色集合的基础持久性存储。
        /// </summary>
        /// <value>
        /// 如果基础持久性存储支持返回角色的<see cref =“ IQueryable” />集合，则为true，否则为false。
        /// </value>
        public virtual bool SupportsQueryableRoles
        {
            get
            {
                ThrowIfDisposed();
                return Store is IQueryableRoleStore<TRole>;
            }
        }

        /// <summary>
        /// 获取一个标志，该标志指示基础持久性存储支持角色的<see cref =“ Claim” />。
        /// </summary>
        /// <value>
        /// true if the underlying persistence store supports <see cref="Claim"/>s for roles, otherwise false.
        /// </value>
        public virtual bool SupportsRoleClaims
        {
            get
            {
                ThrowIfDisposed();
                return Store is IRoleClaimStore<TRole>;
            }
        }

        /// <summary>
        /// 在持久性存储中创建指定的<paramref name =“ role” />。
        /// </summary>
        /// <param name="role">The role to create.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation.
        /// </returns>
        public virtual async Task<IdentityResult> CreateAsync(TRole role)
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            var result = await ValidateRoleAsync(role);
            if (!result.Succeeded)
            {
                return result;
            }
            await UpdateNormalizedRoleNameAsync(role);
            result = await Store.CreateAsync(role, CancellationToken);
            return result;
        }

        /// <summary>
        /// 更新指定的<paramref name =“ role” />的规范化名称。
        /// </summary>
        /// <param name="role">The role whose normalized name needs to be updated.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation.
        /// </returns>
        public virtual async Task UpdateNormalizedRoleNameAsync(TRole role)
        {
            var name = await GetRoleNameAsync(role);
            await Store.SetNormalizedRoleNameAsync(role, NormalizeKey(name), CancellationToken);
        }

        /// <summary>
        /// 更新指定的<paramref name =“ role” />。
        /// </summary>
        /// <param name="role">The role to updated.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> for the update.
        /// </returns>
        public virtual Task<IdentityResult> UpdateAsync(TRole role)
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return UpdateRoleAsync(role);
        }

        /// <summary>
        /// 删除指定的<paramref name =“ role” />。
        /// </summary>
        /// <param name="role">The role to delete.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> for the delete.
        /// </returns>
        public virtual Task<IdentityResult> DeleteAsync(TRole role)
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Store.DeleteAsync(role, CancellationToken);
        }

        /// <summary>
        /// 获取一个标志，该标志指示指定的<paramref name =“ roleName” />存在。
        /// </summary>
        /// <param name="roleName">The role name whose existence should be checked.</param>
        /// <returns>
        /// <see cref =“ Task” />表示异步操作，如果角色名称存在，则为true，否则为false。
        /// </returns>
        public virtual async Task<bool> RoleExistsAsync(string roleName)
        {
            ThrowIfDisposed();
            if (roleName == null)
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            return await FindByNameAsync(NormalizeKey(roleName)) != null;
        }

        /// <summary>
        /// 获取指定的<paramref name =“ key” />的规范化表示。
        /// </summary>
        /// <param name="key">The value to normalize.</param>
        /// <returns>指定的<paramref name =“ key” />的规范化表示形式.</returns>
        public virtual string NormalizeKey(string key)
        {
            return (KeyNormalizer == null) ? key : KeyNormalizer.NormalizeName(key);
        }

        /// <summary>
        /// 查找与指定的<paramref name =“ roleId” />相关的角色（如果有）。
        /// </summary>
        /// <param name="roleId">The role ID whose role should be returned.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the role 
        /// associated with the specified <paramref name="roleId"/>
        /// </returns>
        public virtual Task<TRole> FindByIdAsync(string roleId)
        {
            ThrowIfDisposed();
            return Store.FindByIdAsync(roleId, CancellationToken);
        }

        /// <summary>
        /// 获取指定的<paramref name =“ role” />的名称。
        /// </summary>
        /// <param name="role">The role whose name should be retrieved.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the name of the 
        /// specified <paramref name="role"/>.
        /// </returns>
        public virtual Task<string> GetRoleNameAsync(TRole role)
        {
            ThrowIfDisposed();
            return Store.GetRoleNameAsync(role, CancellationToken);
        }

        /// <summary>
        /// 设置指定的<paramref name =“ role” />的名称。
        /// </summary>
        /// <param name="role">The role whose name should be set.</param>
        /// <param name="name">The name to set.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> SetRoleNameAsync(TRole role, string name)
        {
            ThrowIfDisposed();

            await Store.SetRoleNameAsync(role, name, CancellationToken);
            await UpdateNormalizedRoleNameAsync(role);
            return IdentityResult.Success;
        }

        /// <summary>
        ///获取指定的<paramref name =“ role” />的ID。
        /// </summary>
        /// <param name="role">The role whose ID should be retrieved.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the ID of the 
        /// specified <paramref name="role"/>.
        /// </returns>
        public virtual Task<string> GetRoleIdAsync(TRole role)
        {
            ThrowIfDisposed();
            return Store.GetRoleIdAsync(role, CancellationToken);
        }

        /// <summary>
        /// 查找与指定的<paramref name =“ roleName” />相关的角色（如果有）。
        /// </summary>
        /// <param name="roleName">The name of the role to be returned.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the role 
        /// associated with the specified <paramref name="roleName"/>
        /// </returns>
        public virtual Task<TRole> FindByNameAsync(string roleName)
        {
            ThrowIfDisposed();
            if (roleName == null)
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            return Store.FindByNameAsync(NormalizeKey(roleName), CancellationToken);
        }

        /// <summary>
        ///向角色添加声明。
        /// </summary>
        /// <param name="role">The role to add the claim to.</param>
        /// <param name="claim">The claim to add.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> AddClaimAsync(TRole role, Claim claim)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            await claimStore.AddClaimAsync(role, claim, CancellationToken);
            return await UpdateRoleAsync(role);
        }

        /// <summary>
        /// 从角色中删除claim。
        /// </summary>
        /// <param name="role">The role to remove the claim from.</param>
        /// <param name="claim">The claim to remove.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> RemoveClaimAsync(TRole role, Claim claim)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            await claimStore.RemoveClaimAsync(role, claim, CancellationToken);
            return await UpdateRoleAsync(role);
        }

        /// <summary>
        /// 获取与指定的<paramref name =“ role” />相关的声明列表。
        /// </summary>
        /// <param name="role">The role whose claims should be returned.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the list of <see cref="Claim"/>s
        /// associated with the specified <paramref name="role"/>.
        /// </returns>
        public virtual Task<IList<Claim>> GetClaimsAsync(TRole role)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            return claimStore.GetClaimsAsync(role, CancellationToken);
        }

        /// <summary>
        /// 释放角色管理器使用的所有资源。
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// 释放角色管理器使用的非托管资源。
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                Store.Dispose();
            }
            _disposed = true;
        }

        /// <summary>
        /// 如果验证成功，则应返回<see cref =“ IdentityResult.Success” />。 这是
         ///在通过创建或更新保存角色之前调用。
        /// </summary>
        /// <param name="role">The role</param>
        /// <returns>A <see cref="IdentityResult"/> representing whether validation was successful.</returns>
        protected virtual async Task<IdentityResult> ValidateRoleAsync(TRole role)
        {
            var errors = new List<IdentityError>();
            foreach (var v in RoleValidators)
            {
                var result = await v.ValidateAsync(this, role);
                if (!result.Succeeded)
                {
                    errors.AddRange(result.Errors);
                }
            }
            if (errors.Count > 0)
            {
                Logger.LogWarning(0, "Role {roleId} validation failed: {errors}.", await GetRoleIdAsync(role), string.Join(";", errors.Select(e => e.Code)));
                return IdentityResult.Failed(errors.ToArray());
            }
            return IdentityResult.Success;
        }

        /// <summary>
        ///验证并更新规范化的角色名称后，调用以更新角色。
        /// </summary>
        /// <param name="role">The role.</param>
        /// <returns>Whether the operation was successful.</returns>
        protected virtual async Task<IdentityResult> UpdateRoleAsync(TRole role)
        {
            var result = await ValidateRoleAsync(role);
            if (!result.Succeeded)
            {
                return result;
            }
            await UpdateNormalizedRoleNameAsync(role);
            return await Store.UpdateAsync(role, CancellationToken);
        }

        // IRoleClaimStore methods
        private IRoleClaimStore<TRole> GetClaimStore()
        {
            var cast = Store as IRoleClaimStore<TRole>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIRoleClaimStore);
            }
            return cast;
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
    }
```
### RoleValidator
```
    /// <summary>
    /// 提供角色的默认验证。
    /// </summary>
    /// <typeparam name="TRole">The type encapsulating a role.</typeparam>
    public class RoleValidator<TRole> : IRoleValidator<TRole> where TRole : class
    {
        /// <summary>
        /// 创建<see cref =“ RoleValidator {TRole}” /> /的新实例
        /// </summary>
        /// <param name="errors">The <see cref="IdentityErrorDescriber"/> used to provider error messages.</param>
        public RoleValidator(IdentityErrorDescriber errors = null)
        {
            Describer = errors ?? new IdentityErrorDescriber();
        }

        private IdentityErrorDescriber Describer { get; set; }

        /// <summary>
        /// 将角色验证为异步操作。
        /// </summary>
        /// <param name="manager">The <see cref="RoleManager{TRole}"/> managing the role store.</param>
        /// <param name="role">The role to validate.</param>
        /// <returns>A <see cref="Task{TResult}"/> that represents the <see cref="IdentityResult"/> of the asynchronous validation.</returns>
        public virtual async Task<IdentityResult> ValidateAsync(RoleManager<TRole> manager, TRole role)
        {
            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            var errors = new List<IdentityError>();
            await ValidateRoleName(manager, role, errors);
            if (errors.Count > 0)
            {
                return IdentityResult.Failed(errors.ToArray());
            }
            return IdentityResult.Success;
        }

        private async Task ValidateRoleName(RoleManager<TRole> manager, TRole role,
            ICollection<IdentityError> errors)
        {
            var roleName = await manager.GetRoleNameAsync(role);
            if (string.IsNullOrWhiteSpace(roleName))
            {
                errors.Add(Describer.InvalidRoleName(roleName));
            }
            else
            {
                var owner = await manager.FindByNameAsync(roleName);
                if (owner != null && 
                    !string.Equals(await manager.GetRoleIdAsync(owner), await manager.GetRoleIdAsync(role)))
                {
                    errors.Add(Describer.DuplicateRoleName(roleName));
                }
            }
        }
    }
```
### SignInOptions
```
    /// <summary>
    /// 用于配置登录的选项。
    /// </summary>
    public class SignInOptions
    {
        /// <summary>
        /// 如果用户必须具有已确认的电子邮件地址才能登录，则为 True，否则为 false。
        /// </summary>
        /// <value>如果用户在登录之前具有电子邮件地址，则为true，否则为false。</value>
        public bool RequireConfirmedEmail { get; set; }

        /// <summary>
        /// 获取或设置指示是否需要确认的电话号码才能登录的标志。默认值为 false。
        /// </summary>
        /// <value>如果用户必须具有确认的号码，则为true，否则为false.</value>
        public bool RequireConfirmedPhoneNumber { get; set; }

        /// <summary>
        /// 获取或设置一个标志，指示是否需要确认的 [请参阅 cref]"IUser 确认[TUser]"/* 帐户才能登录。默认值为 false。
        /// </summary>
        /// <value>如果用户必须具有已确认的帐户才能登录，则为 True，否则为 false.</value>
        public bool RequireConfirmedAccount { get; set; }
    }
```
### SignInResult
```
    /// <summary>
    /// 表示登录操作的结果。
    /// </summary>
    public class SignInResult
    {
        private static readonly SignInResult _success = new SignInResult { Succeeded = true };
        private static readonly SignInResult _failed = new SignInResult();
        private static readonly SignInResult _lockedOut = new SignInResult { IsLockedOut = true };
        private static readonly SignInResult _notAllowed = new SignInResult { IsNotAllowed = true };
        private static readonly SignInResult _twoFactorRequired = new SignInResult { RequiresTwoFactor = true };

        /// <summary>
        /// 返回指示登录是否成功的标志。
        /// </summary>
        /// <value>True if the sign-in was successful, otherwise false.</value>
        public bool Succeeded { get; protected set; }

        /// <summary>
        /// 返回指示尝试登录的用户是否已锁定的标志。
        /// </summary>
        /// <value>True if the user attempting to sign-in is locked out, otherwise false.</value>
        public bool IsLockedOut { get; protected set; }

        /// <summary>
        /// 返回标志指示是否不允许尝试登录的用户登录。
        /// </summary>
        /// <value>如果不允许尝试登录的用户登录，则为 True，否则为 false。</value>
        public bool IsNotAllowed { get; protected set; }

        /// <summary>
        ///返回标志指示尝试登录的用户是否需要两个因素身份验证。
        /// </summary>
        /// <value>如果尝试登录的用户需要两个因素身份验证，则为 True，否则为 false。</value>
        public bool RequiresTwoFactor { get; protected set; }

        /// <summary>
        /// 返回表示成功登录的 [请参阅 cref}"SignInResult"/*。
        /// </summary>
        /// <returns>A <see cref="SignInResult"/> that represents a successful sign-in.</returns>
        public static SignInResult Success => _success;

        /// <summary>
        /// 返回表示失败的登录的 [请参阅 cref]"SignInResult"/*。
        /// </summary>
        /// <returns>A <see cref="SignInResult"/> that represents a failed sign-in.</returns>
        public static SignInResult Failed => _failed;

        /// <summary>
        /// 返回一个 [请参阅 cref}"SignInResult"/] 表示登录尝试失败，因为
        用户已注销。
        /// </summary>
        /// <returns>A <see cref="SignInResult"/> that represents sign-in attempt that failed due to the
        /// user being locked out.</returns>
        public static SignInResult LockedOut => _lockedOut;

        /// <summary>
        /// 返回一个 [请参阅 cref}"SignInResult"/] 表示登录尝试失败，因为
        不允许用户登录。
        /// </summary>
        /// <returns>A <see cref="SignInResult"/> that represents sign-in attempt that failed due to the
        /// user is not allowed to sign-in.</returns>
        public static SignInResult NotAllowed => _notAllowed;

        /// <summary>
        /// 返回一个 [请参阅 cref}"SignInResult"/] 表示需要双因素的登录尝试
        认证。
        /// </summary>
        /// <returns>A <see cref="SignInResult"/> that represents sign-in attempt that needs two-factor
        /// authentication.</returns>
        public static SignInResult TwoFactorRequired => _twoFactorRequired;

        /// <summary>
        /// 将当前 [请参阅 cref]"SignInResult}/] 对象的值转换为其等效的字符串表示形式。
        /// </summary>
        /// <returns>A string representation of value of the current <see cref="SignInResult"/> object.</returns>
        public override string ToString()
        {
            return IsLockedOut ? "Lockedout" : 
		   	       IsNotAllowed ? "NotAllowed" : 
			       RequiresTwoFactor ? "RequiresTwoFactor" : 
			       Succeeded ? "Succeeded" : "Failed";
        }
    }
```
### StoreOptions
```
    /// <summary>
    /// 用于存储特定选项
    /// </summary>
    public class StoreOptions
    {
        /// <summary>
        /// 如果设置为正数，则默认的OnModelCreating希望将此值用作任何对象的最大长度
         ///用作键的属性，即 UserId，LoginProvider，ProviderKey。
        /// </summary>
        public int MaxLengthForKeys { get; set; }

        /// <summary>
        /// 如果设置为true，则存储必须为用户保护所有标识数据。
         ///这将通过要求存储实现<see cref =“ IProtectedUserStore {TUser}” />来强制执行。
        /// </summary>
        public bool ProtectPersonalData { get; set; }
    }
```
### TokenOptions
```
    /// <summary>
    /// 用户令牌的选项。
    /// </summary>
    public class TokenOptions
    {
        /// <summary>
        ///电子邮件确认，密码重置和更改电子邮件使用的默认令牌提供者名称。
        /// </summary>
        public static readonly string DefaultProvider = "Default";

        /// <summary>
        /// 电子邮件提供商使用的默认令牌提供商名称。/>。
        /// </summary>
        public static readonly string DefaultEmailProvider = "Email";

        /// <summary>
        /// 电话提供商使用的默认令牌提供商名称。/>。
        /// </summary>
        public static readonly string DefaultPhoneProvider = "Phone";

        /// <summary>
        /// <请参阅cref =“ AuthenticatorTokenProvider” />使用的默认令牌提供者名称。
        /// </summary>
        public static readonly string DefaultAuthenticatorProvider = "Authenticator";

        /// <summary>
        ///将用于使用键作为providerName构造UserTokenProviders。
        /// </summary>
        public Dictionary<string, TokenProviderDescriptor> ProviderMap { get; set; } = new Dictionary<string, TokenProviderDescriptor>();

        /// <summary>
        /// 获取或设置令牌提供程序，该令牌提供程序用于生成帐户确认电子邮件中使用的令牌。
        /// </summary>
        /// <value>
        /// <see cref =“ IUserTwoFactorTokenProvider {TUser}” />用于在帐户确认电子邮件中生成令牌。
        /// </value>
        public string EmailConfirmationTokenProvider { get; set; } = DefaultProvider;

        /// <summary>
        ///获取或设置<see cref =“ IUserTwoFactorTokenProvider {TUser}” /> />，该密码用于在密码重置电子邮件中生成令牌。
        /// </summary>
        /// <value>
        /// <see cref =“ IUserTwoFactorTokenProvider {TUser}” />用于在密码重置电子邮件中生成令牌。
        /// </value>
        public string PasswordResetTokenProvider { get; set; } = DefaultProvider;

        /// <summary>
        ///获取或设置用于在电子邮件更改确认电子邮件中生成令牌的<see cref =“ ChangeEmailTokenProvider” />。
        /// </summary>
        /// <value>
        /// The <see cref="ChangeEmailTokenProvider"/> used to generate tokens used in email change confirmation emails.
        /// </value>
        public string ChangeEmailTokenProvider { get; set; } = DefaultProvider;

        /// <summary>
        /// 获取或设置在更改电话号码时用于生成令牌的<see cref =“ ChangePhoneNumberTokenProvider” />。
        /// </summary>
        /// <value>
        /// The <see cref="ChangePhoneNumberTokenProvider"/> used to generate tokens used when changing phone numbers.
        /// </value>
        public string ChangePhoneNumberTokenProvider { get; set; } = DefaultPhoneProvider;

        /// <summary>
        /// 获取或设置<see cref =“ AuthenticatorTokenProvider” />，该信息用于验证使用身份验证器的两要素登录。
        /// </summary>
        /// <value>
        /// The <see cref="AuthenticatorTokenProvider"/> used to validate two factor sign ins with an authenticator.
        /// </value>
        public string AuthenticatorTokenProvider { get; set; } = DefaultAuthenticatorProvider;

        /// <summary>
        /// 获取或设置用于身份验证方颁发者的颁发者。
        /// </summary>
        public string AuthenticatorIssuer { get; set; } = "Microsoft.AspNetCore.Identity.UI";
    }
```
### TokenProviderDescriptor
```
   /// <summary>
    /// 用于表示<see cref =“ TokenOptions” />的TokenMap中的令牌提供者。
    /// </summary>
    public class TokenProviderDescriptor
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TokenProviderDescriptor"/> class.
        /// </summary>
        /// <param name="type">The concrete type for this token provider.</param>
        public TokenProviderDescriptor(Type type)
        {
            ProviderType = type;
        }

        /// <summary>
        /// 想要用于此令牌提供程序的类型。
        /// </summary>
        public Type ProviderType { get; }

        /// <summary>
        /// 如果指定，则为令牌提供者使用的实例。
        /// </summary>
        public object ProviderInstance { get; set; }
    }
```
### TotpSecurityStampBasedTokenProvider
```
    /// <summary>
    /// 表示令牌提供者，该令牌提供者使用用户的安全戳生成时间码。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public abstract class TotpSecurityStampBasedTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser>
        where TUser : class
    {
        /// <summary>
        /// 为指定的<paramref name =“ user” />和<paramref name =“ purpose” />生成令牌。
        /// </summary>
        /// <param name="purpose">The purpose the token will be used for.</param>
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
        public virtual async Task<string> GenerateAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }
            var token = await manager.CreateSecurityTokenAsync(user);
            var modifier = await GetUserModifierAsync(purpose, manager, user);
            return Rfc6238AuthenticationService.GenerateCode(token, modifier).ToString("D6", CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// 返回一个标志，指示指定的<paramref name =“ token” />对给定有效
         /// <paramref name =“ user” />和<paramref name =“ purpose” />。
        /// </summary>
        /// <param name="purpose">The purpose the token will be used for.</param>
        /// <param name="token">The token to validate.</param>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> that can be used to retrieve user properties.</param>
        /// <param name="user">用户应经过验证.</param>
        /// <returns>
        /// <see cref =“ Task” />代表异步操作，包含标记结果
         ///为指定的</ paramref>验证<paramref name =“ token”>。<paramref name =“ user” />和<paramref name =“ purpose” />。
         ///如果令牌有效，则任务希望返回true，否则返回false。
        /// </returns>
        public virtual async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> manager, TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }
            int code;
            if (!int.TryParse(token, out code))
            {
                return false;
            }
            var securityToken = await manager.CreateSecurityTokenAsync(user);
            var modifier = await GetUserModifierAsync(purpose, manager, user);
            return securityToken != null && Rfc6238AuthenticationService.ValidateCode(securityToken, code, modifier);
        }

        /// <summary>
        ///返回一个常量，提供者和用户唯一的修饰符，用于根据用户信息生成的令牌中的熵。
        /// </summary>
        /// <param name="purpose">The purpose the token will be generated for.</param>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> that can be used to retrieve user properties.</param>
        /// <param name="user">The user a token should be generated for.</param>
        /// <returns>
        /// <see cref =“ task” />代表异步操作，其中包含指定常量的修饰符
         /// <paramref name =“ user” />和<paramref name =“ purpose” />。
        /// </returns>
        public virtual async Task<string> GetUserModifierAsync(string purpose, UserManager<TUser> manager, TUser user)
        {
            if (manager == null)
            {
                throw new ArgumentNullException(nameof(manager));
            }
            var userId = await manager.GetUserIdAsync(user);
            return "Totp:" + purpose + ":" + userId;
        }

        /// <summary>
        /// 返回一个标志，指示提供者是否能够生成适用于以下方面的两因素身份验证令牌的令牌：
         ///指定的<paramref name =“ user” />。
        /// </summary>
        /// <param name="manager">The <see cref="UserManager{TUser}"/> that can be used to retrieve user properties.</param>
        /// <param name="user">The user a token could be generated for.</param>
        /// <returns>
        ///<see cref =“ task” />代表异步操作，如果包含两个，则包含标志标志
         ///此提供者可以为指定的<paramref name =“ user” />生成因子标记。
         ///如果生成了两因素身份验证令牌，则任务希望返回true，否则返回false。
        /// </returns>
        public abstract Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user);
    }
```
### UpperInvariantLookupNormalizer
```
    /// <summary>
    /// 通过将键转换为其大写的不变区域性表示形式来实现<see cref =“ ILookupNormalizer” />。
    /// </summary>
    public sealed class UpperInvariantLookupNormalizer : ILookupNormalizer
    {
        /// <summary>
        /// 返回指定的<paramref name =“ name” />的规范化表示。
        /// </summary>
        /// <param name="name">The key to normalize.</param>
        /// <returns>A normalized representation of the specified <paramref name="name"/>.</returns>
        public string NormalizeName(string name)
        {
            if (name == null)
            {
                return null;
            }
            return name.Normalize().ToUpperInvariant();
        }

        /// <summary>
        /// 返回指定的<paramref name =“ email” />的规范化表示。
        /// </summary>
        /// <param name="email">The email to normalize.</param>
        /// <returns>A normalized representation of the specified <paramref name="email"/>.</returns>
        public string NormalizeEmail(string email) => NormalizeName(email);
    }
```
### UserClaimsPrincipalFactory
```
    /// <summary>
    /// 提供为给定用户创建声明的方法。
    /// </summary>
    /// <typeparam name="TUser">The type used to represent a user.</typeparam>
    public class UserClaimsPrincipalFactory<TUser> : IUserClaimsPrincipalFactory<TUser>
        where TUser : class
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserClaimsPrincipalFactory{TUser}"/> class.
        /// </summary>
        /// <param name="userManager">The <see cref="UserManager{TUser}"/> to retrieve user information from.</param>
        /// <param name="optionsAccessor">The configured <see cref="IdentityOptions"/>.</param>
        public UserClaimsPrincipalFactory(
            UserManager<TUser> userManager,
            IOptions<IdentityOptions> optionsAccessor)
        {
            if (userManager == null)
            {
                throw new ArgumentNullException(nameof(userManager));
            }
            if (optionsAccessor == null || optionsAccessor.Value == null)
            {
                throw new ArgumentNullException(nameof(optionsAccessor));
            }
            UserManager = userManager;
            Options = optionsAccessor.Value;
        }

        /// <summary>
        /// Gets the <see cref="UserManager{TUser}"/> for this factory.
        /// </summary>
        /// <value>
        /// The current <see cref="UserManager{TUser}"/> for this factory instance.
        /// </value>
        public UserManager<TUser> UserManager { get; private set; }

        /// <summary>
        /// Gets the <see cref="IdentityOptions"/> for this factory.
        /// </summary>
        /// <value>
        /// The current <see cref="IdentityOptions"/> for this factory instance.
        /// </value>
        public IdentityOptions Options { get; private set; }

        /// <summary>
        /// 从异步用户创建<see cref =“ ClaimsPrincipal” />。
        /// </summary>
        /// <param name="user">The user to create a <see cref="ClaimsPrincipal"/> from.</param>
        /// <returns><see cref =“ Task” />代表异步创建操作，包含已创建的<see cref =“ ClaimsPrincipal” />.</returns>
        public virtual async Task<ClaimsPrincipal> CreateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var id = await GenerateClaimsAsync(user);
            return new ClaimsPrincipal(id);
        }

        /// <summary>
        /// <see cref =“ Task” />代表初始化创建操作，包含已创建的<see cref =“ ClaimsPrincipal” />
        /// </summary>
        /// <param name="user">The user to create a <see cref="ClaimsIdentity"/> from.</param>
        /// <returns><see cref =“ Task” />代表异步创建操作，其中包含已创建的<see cref =“ ClaimsIdentity” />。</returns>
        protected virtual async Task<ClaimsIdentity> GenerateClaimsAsync(TUser user)
        {
            var userId = await UserManager.GetUserIdAsync(user);
            var userName = await UserManager.GetUserNameAsync(user);
            var id = new ClaimsIdentity("Identity.Application", // REVIEW: Used to match Application scheme
                Options.ClaimsIdentity.UserNameClaimType,
                Options.ClaimsIdentity.RoleClaimType);
            id.AddClaim(new Claim(Options.ClaimsIdentity.UserIdClaimType, userId));
            id.AddClaim(new Claim(Options.ClaimsIdentity.UserNameClaimType, userName));
            if (UserManager.SupportsUserSecurityStamp)
            {
                id.AddClaim(new Claim(Options.ClaimsIdentity.SecurityStampClaimType,
                    await UserManager.GetSecurityStampAsync(user)));
            }
            if (UserManager.SupportsUserClaim)
            {
                id.AddClaims(await UserManager.GetClaimsAsync(user));
            }
            return id;
        }
    }

    /// <summary>
    /// 提供为给定用户创建声明的方法。
    /// </summary>
    /// <typeparam name="TUser">The type used to represent a user.</typeparam>
    /// <typeparam name="TRole">The type used to represent a role.</typeparam>
    public class UserClaimsPrincipalFactory<TUser, TRole> : UserClaimsPrincipalFactory<TUser>
        where TUser : class
        where TRole : class
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UserClaimsPrincipalFactory{TUser, TRole}"/> class.
        /// </summary>
        /// <param name="userManager">The <see cref="UserManager{TUser}"/> to retrieve user information from.</param>
        /// <param name="roleManager">The <see cref="RoleManager{TRole}"/> to retrieve a user's roles from.</param>
        /// <param name="options">The configured <see cref="IdentityOptions"/>.</param>
        public UserClaimsPrincipalFactory(UserManager<TUser> userManager, RoleManager<TRole> roleManager, IOptions<IdentityOptions> options)
            : base(userManager, options)
        {
            if (roleManager == null)
            {
                throw new ArgumentNullException(nameof(roleManager));
            }
            RoleManager = roleManager;
        }

        /// <summary>
        /// Gets the <see cref="RoleManager{TRole}"/> for this factory.
        /// </summary>
        /// <value>
        /// The current <see cref="RoleManager{TRole}"/> for this factory instance.
        /// </value>
        public RoleManager<TRole> RoleManager { get; private set; }

        /// <summary>
        /// 为用户生成声明。
        /// </summary>
        /// <param name="user">The user to create a <see cref="ClaimsIdentity"/> from.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous creation operation, containing the created <see cref="ClaimsIdentity"/>.</returns>
        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(TUser user)
        {
            var id = await base.GenerateClaimsAsync(user);
            if (UserManager.SupportsUserRole)
            {
                var roles = await UserManager.GetRolesAsync(user);
                foreach (var roleName in roles)
                {
                    id.AddClaim(new Claim(Options.ClaimsIdentity.RoleClaimType, roleName));
                    if (RoleManager.SupportsRoleClaims)
                    {
                        var role = await RoleManager.FindByNameAsync(roleName);
                        if (role != null)
                        {
                            id.AddClaims(await RoleManager.GetClaimsAsync(role));
                        }
                    }
                }
            }
            return id;
        }
    }
```
### UserLoginInfo
```
    /// <summary>
    /// 表示登录信息和用户记录的来源。
    /// </summary>
    public class UserLoginInfo
    {
        /// <summary>
        /// Creates a new instance of <see cref="UserLoginInfo"/>
        /// </summary>
        /// <param name="loginProvider">与该登录信息关联的提供者。</param>
        /// <param name="providerKey">该用户的唯一标识符由登录提供程序提供。</param>
        /// <param name="displayName">该用户的显示名称由登录提供程序提供。</param>
        public UserLoginInfo(string loginProvider, string providerKey, string displayName)
        {
            LoginProvider = loginProvider;
            ProviderKey = providerKey;
            ProviderDisplayName = displayName;
        }

        /// <summary>
        /// 获取或设置<see cref =“ UserLoginInfo” />的实例的提供程序。
        /// </summary>
        /// <value>此实例的提供者<see cref =“ UserLoginInfo” /></value>
        /// <remarks>
        /// 提供者的示例可以是本地，Facebook，Google等。
        /// </remarks>
        public string LoginProvider { get; set; }

        /// <summary>
        /// 获取或设置登录提供者提供的用户身份的唯一标识符。
        /// </summary>
        /// <value>
        /// 登录提供者提供的用户身份的唯一标识符。
        /// </value>
        /// <remarks>
        /// 这将由提供程序来唯一，例如@microsoft作为Twitter提供程序密钥。
        /// </remarks>
        public string ProviderKey { get; set; }

        /// <summary>
        /// 获取或设置提供程序的显示名称。
        /// </summary>
        /// <value>
        /// 提供程序的显示名称。
        /// </value>
        public string ProviderDisplayName { get; set; }
    }
```
### UserManager
```
    /// <summary>
    ///提供用于在持久性存储中管理用户的API。
    /// </summary>
    /// <typeparam name="TUser">The type encapsulating a user.</typeparam>
    public class UserManager<TUser> : IDisposable where TUser : class
    {
        /// <summary>
        /// 用于与密码重置相关的数据保护目的。
        /// </summary>
        public const string ResetPasswordTokenPurpose = "ResetPassword";

        /// <summary>
        /// 用于更改电话号码方法的数据保护目的。
        /// </summary>
        public const string ChangePhoneNumberTokenPurpose = "ChangePhoneNumber";

        /// <summary>
        /// 用于电子邮件确认相关方法的数据保护目的。
        /// </summary>
        public const string ConfirmEmailTokenPurpose = "EmailConfirmation";

        private readonly Dictionary<string, IUserTwoFactorTokenProvider<TUser>> _tokenProviders =
            new Dictionary<string, IUserTwoFactorTokenProvider<TUser>>();

        private TimeSpan _defaultLockout = TimeSpan.Zero;
        private bool _disposed;
        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        private IServiceProvider _services;

        /// <summary>
        /// 用于取消操作的取消令牌。
        /// </summary>
        protected virtual CancellationToken CancellationToken => CancellationToken.None;

        /// <summary>
        /// 构造<see cref =“ UserManager {TUser}” />的新实例。
        /// </summary>
        /// <param name="store">管理想要操作的持久性存储.</param>
        /// <param name="optionsAccessor">用于访问<see cref =“ IdentityOptions” />的访问器.</param>
        /// <param name="passwordHasher">保存密码时要使用的密码哈希实现.</param>
        /// <param name="userValidators">的<see cref =“ IUserValidator {TUser}” /> />的集合，以验证用户的身份。</param>
        /// <param name="passwordValidators"><see cref =“ IPasswordValidator {TUser}” />的集合来验证密码。</param>
        /// <param name="keyNormalizer"><为用户生成索引键时使用的<see cref =“ ILookupNormalizer” />。</param>
        /// <param name="errors"><see cref =“ IdentityErrorDescriber” />用于提供错误消息。</param>
        /// <param name="services">The <see cref="IServiceProvider"/> 用于解决服务。</param>
        /// <param name="logger">记录器用于记录消息，警告和错误.</param>
        public UserManager(IUserStore<TUser> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<TUser> passwordHasher,
            IEnumerable<IUserValidator<TUser>> userValidators,
            IEnumerable<IPasswordValidator<TUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<TUser>> logger)
        {
            if (store == null)
            {
                throw new ArgumentNullException(nameof(store));
            }
            Store = store;
            Options = optionsAccessor?.Value ?? new IdentityOptions();
            PasswordHasher = passwordHasher;
            KeyNormalizer = keyNormalizer;
            ErrorDescriber = errors;
            Logger = logger;

            if (userValidators != null)
            {
                foreach (var v in userValidators)
                {
                    UserValidators.Add(v);
                }
            }
            if (passwordValidators != null)
            {
                foreach (var v in passwordValidators)
                {
                    PasswordValidators.Add(v);
                }
            }

            _services = services;
            if (services != null)
            {
                foreach (var providerName in Options.Tokens.ProviderMap.Keys)
                {
                    var description = Options.Tokens.ProviderMap[providerName];

                    var provider = (description.ProviderInstance ?? services.GetRequiredService(description.ProviderType))
                        as IUserTwoFactorTokenProvider<TUser>;
                    if (provider != null)
                    {
                        RegisterTokenProvider(providerName, provider);
                    }
                }
            }                

            if (Options.Stores.ProtectPersonalData)
            {
                if (!(Store is IProtectedUserStore<TUser>))
                {
                    throw new InvalidOperationException(Resources.StoreNotIProtectedUserStore);
                }
                if (services.GetService<ILookupProtector>() == null)
                {
                    throw new InvalidOperationException(Resources.NoPersonalDataProtector);
                }
            }
        }

        /// <summary>
        /// 获取或设置管理器进行操作的持久性存储。
        /// </summary>
        /// <value>The persistence store the manager operates over.</value>
        protected internal IUserStore<TUser> Store { get; set; }

        /// <summary>
        /// The <see cref="ILogger"/> used to log messages from the manager.
        /// </summary>
        /// <value>
        /// The <see cref="ILogger"/> used to log messages from the manager.
        /// </value>
        public virtual ILogger Logger { get; set; }

        /// <summary>
        /// The <see cref="IPasswordHasher{TUser}"/> used to hash passwords.
        /// </summary>
        public IPasswordHasher<TUser> PasswordHasher { get; set; }

        /// <summary>
        /// The <see cref="IUserValidator{TUser}"/> used to validate users.
        /// </summary>
        public IList<IUserValidator<TUser>> UserValidators { get; } = new List<IUserValidator<TUser>>();

        /// <summary>
        /// The <see cref="IPasswordValidator{TUser}"/> used to validate passwords.
        /// </summary>
        public IList<IPasswordValidator<TUser>> PasswordValidators { get; } = new List<IPasswordValidator<TUser>>();

        /// <summary>
        /// The <see cref="ILookupNormalizer"/> used to normalize things like user and role names.
        /// </summary>
        public ILookupNormalizer KeyNormalizer { get; set; }
        
        /// <summary>
        /// The <see cref="IdentityErrorDescriber"/> used to generate error messages.
        /// </summary>
        public IdentityErrorDescriber ErrorDescriber { get; set; }

        /// <summary>
        /// The <see cref="IdentityOptions"/> used to configure Identity.
        /// </summary>
        public IdentityOptions Options { get; set; }

        /// <summary>
        /// 获取一个标志，该标志指示后备用户存储是否支持身份验证令牌。
        /// </summary>
        /// <value>
        /// true if the backing user store supports authentication tokens, otherwise false.
        /// </value>
        public virtual bool SupportsUserAuthenticationTokens
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserAuthenticationTokenStore<TUser>;
            }
        }

        /// <summary>
        /// 获取一个标志，该标志指示后备用户存储是否支持用户身份验证器。
        /// </summary>
        /// <value>
        /// true if the backing user store supports a user authenticator, otherwise false.
        /// </value>
        public virtual bool SupportsUserAuthenticatorKey
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserAuthenticatorKeyStore<TUser>;
            }
        }

        /// <summary>
        ///获取一个标志，该标志指示后备用户存储是否支持恢复代码。
        /// </summary>
        /// <value>
        /// true if the backing user store supports a user authenticator, otherwise false.
        /// </value>
        public virtual bool SupportsUserTwoFactorRecoveryCodes
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserTwoFactorRecoveryCodeStore<TUser>;
            }
        }

        /// <summary>
        ///获取一个标志，该标志指示后备用户存储是否支持两因素身份验证。
        /// </summary>
        /// <value>
        /// true if the backing user store supports user two factor authentication, otherwise false.
        /// </value>
        public virtual bool SupportsUserTwoFactor
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserTwoFactorStore<TUser>;
            }
        }

        /// <summary>
        ///获取一个标志，该标志指示后备用户存储是否支持用户密码。
        /// </summary>
        /// <value>
        /// true if the backing user store supports user passwords, otherwise false.
        /// </value>
        public virtual bool SupportsUserPassword
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserPasswordStore<TUser>;
            }
        }

        /// <summary>
        ///获取一个标志，该标志指示后备用户存储是否支持安全标记。
        /// </summary>
        /// <value>
        /// true if the backing user store supports user security stamps, otherwise false.
        /// </value>
        public virtual bool SupportsUserSecurityStamp
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserSecurityStampStore<TUser>;
            }
        }

        /// <summary>
        /// 获取一个标志，该标志指示后备用户存储是否支持用户角色。
        /// </summary>
        /// <value>
        /// true if the backing user store supports user roles, otherwise false.
        /// </value>
        public virtual bool SupportsUserRole
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserRoleStore<TUser>;
            }
        }

        /// <summary>
        /// 获取一个标志，该标志指示后备用户存储是否支持外部登录。
        /// </summary>
        /// <value>
        /// true if the backing user store supports external logins, otherwise false.
        /// </value>
        public virtual bool SupportsUserLogin
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserLoginStore<TUser>;
            }
        }

        /// <summary>
        /// 获取一个标志，该标志指示后备用户存储是否支持用户电子邮件。
         /// </ summary>
        /// <value>
        /// true if the backing user store supports user emails, otherwise false.
        /// </value>
        public virtual bool SupportsUserEmail
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserEmailStore<TUser>;
            }
        }

        /// <summary>
        ///获取一个标志，该标志指示后备用户存储是否支持用户电话号码。
        /// </summary>
        /// <value>
        /// true if the backing user store supports user telephone numbers, otherwise false.
        /// </value>
        public virtual bool SupportsUserPhoneNumber
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserPhoneNumberStore<TUser>;
            }
        }

        /// <summary>
        /// 获取一个标志，该标志指示后备用户商店是否支持用户声明。
        /// </summary>
        /// <value>
        /// true if the backing user store supports user claims, otherwise false.
        /// </value>
        public virtual bool SupportsUserClaim
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserClaimStore<TUser>;
            }
        }

        /// <summary>
        ///获取一个标志，该标志指示后备用户存储是否支持用户锁定。
        /// </summary>
        /// <value>
        /// true if the backing user store supports user lock-outs, otherwise false.
        /// </value>
        public virtual bool SupportsUserLockout
        {
            get
            {
                ThrowIfDisposed();
                return Store is IUserLockoutStore<TUser>;
            }
        }

        /// <summary>
        /// 获取一个标志，该标志指示后备用户存储是否支持返回
         /// <请参阅cref =“ IQueryable” />信息集合。
        /// </summary>
        /// <value>
        /// true if the backing user store supports returning <see cref="IQueryable"/> collections of
        /// information, otherwise false.
        /// </value>
        public virtual bool SupportsQueryableUsers
        {
            get
            {
                ThrowIfDisposed();
                return Store is IQueryableUserStore<TUser>;
            }
        }

        /// <summary>
        ///    如果商店位于IQueryableUserStore，则返回用户的IQueryable
        /// </summary>
        public virtual IQueryable<TUser> Users
        {
            get
            {
                var queryableStore = Store as IQueryableUserStore<TUser>;
                if (queryableStore == null)
                {
                    throw new NotSupportedException(Resources.StoreNotIQueryableUserStore);
                }
                return queryableStore.Users;
            }
        }

        /// <summary>
        /// Releases all resources used by the user manager.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Returns the Name claim value if present otherwise returns null.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/> instance.</param>
        /// <returns>The Name claim value, or null if the claim is not present.</returns>
        /// <remarks>The Name claim is identified by <see cref="ClaimsIdentity.DefaultNameClaimType"/>.</remarks>
        public virtual string GetUserName(ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }
            return principal.FindFirstValue(Options.ClaimsIdentity.UserNameClaimType);
        }

        /// <summary>
        /// Returns the User ID claim value if present otherwise returns null.
        /// </summary>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/> instance.</param>
        /// <returns>The User ID claim value, or null if the claim is not present.</returns>
        /// <remarks>The User ID claim is identified by <see cref="ClaimTypes.NameIdentifier"/>.</remarks>
        public virtual string GetUserId(ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }
            return principal.FindFirstValue(Options.ClaimsIdentity.UserIdClaimType);
        }

        /// <summary>
        /// Returns the user corresponding to the IdentityOptions.ClaimsIdentity.UserIdClaimType claim in
        /// the principal or null.
        /// </summary>
        /// <param name="principal">The principal which contains the user id claim.</param>
        /// <returns>The user corresponding to the IdentityOptions.ClaimsIdentity.UserIdClaimType claim in
        /// the principal or null</returns>
        public virtual Task<TUser> GetUserAsync(ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }
            var id = GetUserId(principal);
            return id == null ? Task.FromResult<TUser>(null) : FindByIdAsync(id);
        }

        /// <summary>
        /// Generates a value suitable for use in concurrency tracking.
        /// </summary>
        /// <param name="user">The user to generate the stamp for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the security
        /// stamp for the specified <paramref name="user"/>.
        /// </returns>
        public virtual Task<string> GenerateConcurrencyStampAsync(TUser user)
        {
            return Task.FromResult(Guid.NewGuid().ToString());
        }

        /// <summary>
        /// Creates the specified <paramref name="user"/> in the backing store with no password,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            await UpdateSecurityStampInternal(user);
            var result = await ValidateUserAsync(user);
            if (!result.Succeeded)
            {
                return result;
            }
            if (Options.Lockout.AllowedForNewUsers && SupportsUserLockout)
            {
                await GetUserLockoutStore().SetLockoutEnabledAsync(user, true, CancellationToken);
            }
            await UpdateNormalizedUserNameAsync(user);
            await UpdateNormalizedEmailAsync(user);

            return await Store.CreateAsync(user, CancellationToken);
        }

        /// <summary>
        /// Updates the specified <paramref name="user"/> in the backing store.
        /// </summary>
        /// <param name="user">The user to update.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual Task<IdentityResult> UpdateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return UpdateUserAsync(user);
        }

        /// <summary>
        /// Deletes the specified <paramref name="user"/> from the backing store.
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual Task<IdentityResult> DeleteAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Store.DeleteAsync(user, CancellationToken);
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId">The user ID to search for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
        /// </returns>
        public virtual Task<TUser> FindByIdAsync(string userId)
        {
            ThrowIfDisposed();
            return Store.FindByIdAsync(userId, CancellationToken);
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified user name.
        /// </summary>
        /// <param name="userName">The user name to search for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userName"/> if it exists.
        /// </returns>
        public virtual async Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();
            if (userName == null)
            {
                throw new ArgumentNullException(nameof(userName));
            }
            userName = NormalizeName(userName);

            var user = await Store.FindByNameAsync(userName, CancellationToken);

            // Need to potentially check all keys
            if (user == null && Options.Stores.ProtectPersonalData)
            {
                var keyRing = _services.GetService<ILookupProtectorKeyRing>();
                var protector = _services.GetService<ILookupProtector>();
                if (keyRing != null && protector != null)
                {
                    foreach (var key in keyRing.GetAllKeyIds())
                    {
                        var oldKey = protector.Protect(key, userName);
                        user = await Store.FindByNameAsync(oldKey, CancellationToken);
                        if (user != null)
                        {
                            return user;
                        }
                    }
                }
            }
            return user;
        }

        /// <summary>
        /// Creates the specified <paramref name="user"/> in the backing store with given password,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="password">The password for the user to hash and store.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> CreateAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            var result = await UpdatePasswordHash(passwordStore, user, password);
            if (!result.Succeeded)
            {
                return result;
            }
            return await CreateAsync(user);
        }

        /// <summary>
        /// Normalize user or role name for consistent comparisons.
        /// </summary>
        /// <param name="name">The name to normalize.</param>
        /// <returns>A normalized value representing the specified <paramref name="name"/>.</returns>
        public virtual string NormalizeName(string name)
            =>  (KeyNormalizer == null) ? name : KeyNormalizer.NormalizeName(name);

        /// <summary>
        /// Normalize email for consistent comparisons.
        /// </summary>
        /// <param name="email">The email to normalize.</param>
        /// <returns>A normalized value representing the specified <paramref name="email"/>.</returns>
        public virtual string NormalizeEmail(string email)
            =>  (KeyNormalizer == null) ? email : KeyNormalizer.NormalizeEmail(email);
        
        private string ProtectPersonalData(string data)
        {
            if (Options.Stores.ProtectPersonalData)
            {
                var keyRing = _services.GetService<ILookupProtectorKeyRing>();
                var protector = _services.GetService<ILookupProtector>();
                return protector.Protect(keyRing.CurrentKeyId, data);
            }
            return data;
        }

        /// <summary>
        /// Updates the normalized user name for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose user name should be normalized and updated.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public virtual async Task UpdateNormalizedUserNameAsync(TUser user)
        {
            var normalizedName = NormalizeName(await GetUserNameAsync(user));
            normalizedName = ProtectPersonalData(normalizedName);
            await Store.SetNormalizedUserNameAsync(user, normalizedName, CancellationToken);
        }

        /// <summary>
        /// Gets the user name for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose name should be retrieved.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the name for the specified <paramref name="user"/>.</returns>
        public virtual async Task<string> GetUserNameAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await Store.GetUserNameAsync(user, CancellationToken);
        }

        /// <summary>
        /// Sets the given <paramref name="userName" /> for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose name should be set.</param>
        /// <param name="userName">The user name to set.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public virtual async Task<IdentityResult> SetUserNameAsync(TUser user, string userName)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await Store.SetUserNameAsync(user, userName, CancellationToken);
            await UpdateSecurityStampInternal(user);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Gets the user identifier for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose identifier should be retrieved.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the identifier for the specified <paramref name="user"/>.</returns>
        public virtual async Task<string> GetUserIdAsync(TUser user)
        {
            ThrowIfDisposed();
            return await Store.GetUserIdAsync(user, CancellationToken);
        }

        /// <summary>
        /// Returns a flag indicating whether the given <paramref name="password"/> is valid for the
        /// specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose password should be validated.</param>
        /// <param name="password">The password to validate</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing true if
        /// the specified <paramref name="password" /> matches the one store for the <paramref name="user"/>,
        /// otherwise false.</returns>
        public virtual async Task<bool> CheckPasswordAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            if (user == null)
            {
                return false;
            }

            var result = await VerifyPasswordAsync(passwordStore, user, password);
            if (result == PasswordVerificationResult.SuccessRehashNeeded)
            {
                await UpdatePasswordHash(passwordStore, user, password, validatePassword: false);
                await UpdateUserAsync(user);
            }

            var success = result != PasswordVerificationResult.Failed;
            if (!success)
            {
                Logger.LogWarning(0, "Invalid password for user {userId}.", await GetUserIdAsync(user));
            }
            return success;
        }

        /// <summary>
        /// Gets a flag indicating whether the specified <paramref name="user"/> has a password.
        /// </summary>
        /// <param name="user">The user to return a flag for, indicating whether they have a password or not.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, returning true if the specified <paramref name="user"/> has a password
        /// otherwise false.
        /// </returns>
        public virtual Task<bool> HasPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return passwordStore.HasPasswordAsync(user, CancellationToken);
        }

        /// <summary>
        /// Adds the <paramref name="password"/> to the specified <paramref name="user"/> only if the user
        /// does not already have a password.
        /// </summary>
        /// <param name="user">The user whose password should be set.</param>
        /// <param name="password">The password to set.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> AddPasswordAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var hash = await passwordStore.GetPasswordHashAsync(user, CancellationToken);
            if (hash != null)
            {
                Logger.LogWarning(1, "User {userId} already has a password.", await GetUserIdAsync(user));
                return IdentityResult.Failed(ErrorDescriber.UserAlreadyHasPassword());
            }
            var result = await UpdatePasswordHash(passwordStore, user, password);
            if (!result.Succeeded)
            {
                return result;
            }
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Changes a user's password after confirming the specified <paramref name="currentPassword"/> is correct,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose password should be set.</param>
        /// <param name="currentPassword">The current password to validate before changing.</param>
        /// <param name="newPassword">The new password to set for the specified <paramref name="user"/>.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> ChangePasswordAsync(TUser user, string currentPassword, string newPassword)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }


            if (await VerifyPasswordAsync(passwordStore, user, currentPassword) != PasswordVerificationResult.Failed)
            {
                var result = await UpdatePasswordHash(passwordStore, user, newPassword);
                if (!result.Succeeded)
                {
                    return result;
                }
                return await UpdateUserAsync(user);
            }
            Logger.LogWarning(2, "Change password failed for user {userId}.", await GetUserIdAsync(user));
            return IdentityResult.Failed(ErrorDescriber.PasswordMismatch());
        }

        /// <summary>
        /// Removes a user's password.
        /// </summary>
        /// <param name="user">The user whose password should be removed.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> RemovePasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            var passwordStore = GetPasswordStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await UpdatePasswordHash(passwordStore, user, null, validatePassword: false);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Returns a <see cref="PasswordVerificationResult"/> indicating the result of a password hash comparison.
        /// </summary>
        /// <param name="store">The store containing a user's password.</param>
        /// <param name="user">The user whose password should be verified.</param>
        /// <param name="password">The password to verify.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="PasswordVerificationResult"/>
        /// of the operation.
        /// </returns>
        protected virtual async Task<PasswordVerificationResult> VerifyPasswordAsync(IUserPasswordStore<TUser> store, TUser user, string password)
        {
            var hash = await store.GetPasswordHashAsync(user, CancellationToken);
            if (hash == null)
            {
                return PasswordVerificationResult.Failed;
            }
            return PasswordHasher.VerifyHashedPassword(user, hash, password);
        }

        /// <summary>
        /// Get the security stamp for the specified <paramref name="user" />.
        /// </summary>
        /// <param name="user">The user whose security stamp should be set.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the security stamp for the specified <paramref name="user"/>.</returns>
        public virtual async Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            var securityStore = GetSecurityStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var stamp = await securityStore.GetSecurityStampAsync(user, CancellationToken);
            if (stamp == null) 
            {
                Logger.LogWarning(15, "GetSecurityStampAsync for user {userId} failed because stamp was null.", await GetUserIdAsync(user));
                throw new InvalidOperationException(Resources.NullSecurityStamp);
            }
            return stamp;
        }

        /// <summary>
        /// Regenerates the security stamp for the specified <paramref name="user" />.
        /// </summary>
        /// <param name="user">The user whose security stamp should be regenerated.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        /// <remarks>
        /// Regenerating a security stamp will sign out any saved login for the user.
        /// </remarks>
        public virtual async Task<IdentityResult> UpdateSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            GetSecurityStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await UpdateSecurityStampInternal(user);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Generates a password reset token for the specified <paramref name="user"/>, using
        /// the configured password reset token provider.
        /// </summary>
        /// <param name="user">The user to generate a password reset token for.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation,
        /// containing a password reset token for the specified <paramref name="user"/>.</returns>
        public virtual Task<string> GeneratePasswordResetTokenAsync(TUser user)
        {
            ThrowIfDisposed();
            return GenerateUserTokenAsync(user, Options.Tokens.PasswordResetTokenProvider, ResetPasswordTokenPurpose);
        }

        /// <summary>
        /// Resets the <paramref name="user"/>'s password to the specified <paramref name="newPassword"/> after
        /// validating the given password reset <paramref name="token"/>.
        /// </summary>
        /// <param name="user">The user whose password should be reset.</param>
        /// <param name="token">The password reset token to verify.</param>
        /// <param name="newPassword">The new password to set if reset token verification succeeds.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> ResetPasswordAsync(TUser user, string token, string newPassword)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // Make sure the token is valid and the stamp matches
            if (!await VerifyUserTokenAsync(user, Options.Tokens.PasswordResetTokenProvider, ResetPasswordTokenPurpose, token))
            {
                return IdentityResult.Failed(ErrorDescriber.InvalidToken());
            }
            var result = await UpdatePasswordHash(user, newPassword, validatePassword: true);
            if (!result.Succeeded)
            {
                return result;
            }
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Retrieves the user associated with the specified external login provider and login provider key.
        /// </summary>
        /// <param name="loginProvider">The login provider who provided the <paramref name="providerKey"/>.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing the user, if any which matched the specified login provider and key.
        /// </returns>
        public virtual Task<TUser> FindByLoginAsync(string loginProvider, string providerKey)
        {
            ThrowIfDisposed();
            var loginStore = GetLoginStore();
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }
            if (providerKey == null)
            {
                throw new ArgumentNullException(nameof(providerKey));
            }
            return loginStore.FindByLoginAsync(loginProvider, providerKey, CancellationToken);
        }

        /// <summary>
        /// Attempts to remove the provided external login information from the specified <paramref name="user"/>.
        /// and returns a flag indicating whether the removal succeed or not.
        /// </summary>
        /// <param name="user">The user to remove the login information from.</param>
        /// <param name="loginProvider">The login provide whose information should be removed.</param>
        /// <param name="providerKey">The key given by the external login provider for the specified user.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> RemoveLoginAsync(TUser user, string loginProvider, string providerKey)
        {
            ThrowIfDisposed();
            var loginStore = GetLoginStore();
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }
            if (providerKey == null)
            {
                throw new ArgumentNullException(nameof(providerKey));
            }
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await loginStore.RemoveLoginAsync(user, loginProvider, providerKey, CancellationToken);
            await UpdateSecurityStampInternal(user);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Adds an external <see cref="UserLoginInfo"/> to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the login to.</param>
        /// <param name="login">The external <see cref="UserLoginInfo"/> to add to the specified <paramref name="user"/>.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> AddLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            var loginStore = GetLoginStore();
            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var existingUser = await FindByLoginAsync(login.LoginProvider, login.ProviderKey);
            if (existingUser != null)
            {
                Logger.LogWarning(4, "AddLogin for user {userId} failed because it was already associated with another user.", await GetUserIdAsync(user));
                return IdentityResult.Failed(ErrorDescriber.LoginAlreadyAssociated());
            }
            await loginStore.AddLoginAsync(user, login, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Retrieves the associated logins for the specified <param ref="user"/>.
        /// </summary>
        /// <param name="user">The user whose associated logins to retrieve.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing a list of <see cref="UserLoginInfo"/> for the specified <paramref name="user"/>, if any.
        /// </returns>
        public virtual async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            ThrowIfDisposed();
            var loginStore = GetLoginStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await loginStore.GetLoginsAsync(user, CancellationToken);
        }

        /// <summary>
        /// Adds the specified <paramref name="claim"/> to the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claim">The claim to add.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual Task<IdentityResult> AddClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return AddClaimsAsync(user, new Claim[] { claim });
        }

        /// <summary>
        /// Adds the specified <paramref name="claims"/> to the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claims">The claims to add.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> AddClaimsAsync(TUser user, IEnumerable<Claim> claims)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await claimStore.AddClaimsAsync(user, claims, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Replaces the given <paramref name="claim"/> on the specified <paramref name="user"/> with the <paramref name="newClaim"/>
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param>
        /// <param name="claim">The claim to replace.</param>
        /// <param name="newClaim">The new claim to replace the existing <paramref name="claim"/> with.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            if (newClaim == null)
            {
                throw new ArgumentNullException(nameof(newClaim));
            }
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await claimStore.ReplaceClaimAsync(user, claim, newClaim, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Removes the specified <paramref name="claim"/> from the given <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the specified <paramref name="claim"/> from.</param>
        /// <param name="claim">The <see cref="Claim"/> to remove.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual Task<IdentityResult> RemoveClaimAsync(TUser user, Claim claim)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            return RemoveClaimsAsync(user, new Claim[] { claim });
        }

        /// <summary>
        /// Removes the specified <paramref name="claims"/> from the given <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the specified <paramref name="claims"/> from.</param>
        /// <param name="claims">A collection of <see cref="Claim"/>s to remove.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            await claimStore.RemoveClaimsAsync(user, claims, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Gets a list of <see cref="Claim"/>s to be belonging to the specified <paramref name="user"/> as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose claims to retrieve.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <see cref="Claim"/>s.
        /// </returns>
        public virtual async Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            ThrowIfDisposed();
            var claimStore = GetClaimStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await claimStore.GetClaimsAsync(user, CancellationToken);
        }

        /// <summary>
        /// Add the specified <paramref name="user"/> to the named role.
        /// </summary>
        /// <param name="user">The user to add to the named role.</param>
        /// <param name="role">The name of the role to add the user to.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> AddToRoleAsync(TUser user, string role)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var normalizedRole = NormalizeName(role);
            if (await userRoleStore.IsInRoleAsync(user, normalizedRole, CancellationToken))
            {
                return await UserAlreadyInRoleError(user, role);
            }
            await userRoleStore.AddToRoleAsync(user, normalizedRole, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Add the specified <paramref name="user"/> to the named roles.
        /// </summary>
        /// <param name="user">The user to add to the named roles.</param>
        /// <param name="roles">The name of the roles to add the user to.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> AddToRolesAsync(TUser user, IEnumerable<string> roles)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (roles == null)
            {
                throw new ArgumentNullException(nameof(roles));
            }

            foreach (var role in roles.Distinct())
            {
                var normalizedRole = NormalizeName(role);
                if (await userRoleStore.IsInRoleAsync(user, normalizedRole, CancellationToken))
                {
                    return await UserAlreadyInRoleError(user, role);
                }
                await userRoleStore.AddToRoleAsync(user, normalizedRole, CancellationToken);
            }
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Removes the specified <paramref name="user"/> from the named role.
        /// </summary>
        /// <param name="user">The user to remove from the named role.</param>
        /// <param name="role">The name of the role to remove the user from.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> RemoveFromRoleAsync(TUser user, string role)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var normalizedRole = NormalizeName(role);
            if (!await userRoleStore.IsInRoleAsync(user, normalizedRole, CancellationToken))
            {
                return await UserNotInRoleError(user, role);
            }
            await userRoleStore.RemoveFromRoleAsync(user, normalizedRole, CancellationToken);
            return await UpdateUserAsync(user);
        }

        private async Task<IdentityResult> UserAlreadyInRoleError(TUser user, string role)
        {
            Logger.LogWarning(5, "User {userId} is already in role {role}.", await GetUserIdAsync(user), role);
            return IdentityResult.Failed(ErrorDescriber.UserAlreadyInRole(role));
        }

        private async Task<IdentityResult> UserNotInRoleError(TUser user, string role)
        {
            Logger.LogWarning(6, "User {userId} is not in role {role}.", await GetUserIdAsync(user), role);
            return IdentityResult.Failed(ErrorDescriber.UserNotInRole(role));
        }

        /// <summary>
        /// Removes the specified <paramref name="user"/> from the named roles.
        /// </summary>
        /// <param name="user">The user to remove from the named roles.</param>
        /// <param name="roles">The name of the roles to remove the user from.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> RemoveFromRolesAsync(TUser user, IEnumerable<string> roles)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (roles == null)
            {
                throw new ArgumentNullException(nameof(roles));
            }

            foreach (var role in roles)
            {
                var normalizedRole = NormalizeName(role);
                if (!await userRoleStore.IsInRoleAsync(user, normalizedRole, CancellationToken))
                {
                    return await UserNotInRoleError(user, role);
                }
                await userRoleStore.RemoveFromRoleAsync(user, normalizedRole, CancellationToken);
            }
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Gets a list of role names the specified <paramref name="user"/> belongs to.
        /// </summary>
        /// <param name="user">The user whose role names to retrieve.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing a list of role names.</returns>
        public virtual async Task<IList<string>> GetRolesAsync(TUser user)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await userRoleStore.GetRolesAsync(user, CancellationToken);
        }

        /// <summary>
        /// Returns a flag indicating whether the specified <paramref name="user"/> is a member of the given named role.
        /// </summary>
        /// <param name="user">The user whose role membership should be checked.</param>
        /// <param name="role">The name of the role to be checked.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing a flag indicating whether the specified <paramref name="user"/> is
        /// a member of the named role.
        /// </returns>
        public virtual async Task<bool> IsInRoleAsync(TUser user, string role)
        {
            ThrowIfDisposed();
            var userRoleStore = GetUserRoleStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await userRoleStore.IsInRoleAsync(user, NormalizeName(role), CancellationToken);
        }

        /// <summary>
        /// Gets the email address for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email should be returned.</param>
        /// <returns>The task object containing the results of the asynchronous operation, the email address for the specified <paramref name="user"/>.</returns>
        public virtual async Task<string> GetEmailAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetEmailStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await store.GetEmailAsync(user, CancellationToken);
        }

        /// <summary>
        /// Sets the <paramref name="email"/> address for a <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email should be set.</param>
        /// <param name="email">The email to set.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> SetEmailAsync(TUser user, string email)
        {
            ThrowIfDisposed();
            var store = GetEmailStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await store.SetEmailAsync(user, email, CancellationToken);
            await store.SetEmailConfirmedAsync(user, false, CancellationToken);
            await UpdateSecurityStampInternal(user);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Gets the user, if any, associated with the normalized value of the specified email address.
        /// Note: Its recommended that identityOptions.User.RequireUniqueEmail be set to true when using this method, otherwise
        /// the store may throw if there are users with duplicate emails.
        /// </summary>
        /// <param name="email">The email address to return the user for.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the user, if any, associated with a normalized value of the specified email address.
        /// </returns>
        public virtual async Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();
            var store = GetEmailStore();
            if (email == null)
            {
                throw new ArgumentNullException(nameof(email));
            }

            email = NormalizeEmail(email);
            var user = await store.FindByEmailAsync(email, CancellationToken);

            // Need to potentially check all keys
            if (user == null && Options.Stores.ProtectPersonalData)
            {
                var keyRing = _services.GetService<ILookupProtectorKeyRing>();
                var protector = _services.GetService<ILookupProtector>();
                if (keyRing != null && protector != null)
                {
                    foreach (var key in keyRing.GetAllKeyIds())
                    {
                        var oldKey = protector.Protect(key, email);
                        user = await store.FindByEmailAsync(oldKey, CancellationToken);
                        if (user != null)
                        {
                            return user;
                        }
                    }
                }
            }
            return user;
        }

        /// <summary>
        /// Updates the normalized email for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email address should be normalized and updated.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public virtual async Task UpdateNormalizedEmailAsync(TUser user)
        {
            var store = GetEmailStore(throwOnFail: false);
            if (store != null)
            {
                var email = await GetEmailAsync(user);
                await store.SetNormalizedEmailAsync(user, ProtectPersonalData(NormalizeEmail(email)), CancellationToken);
            }
        }

        /// <summary>
        /// Generates an email confirmation token for the specified user.
        /// </summary>
        /// <param name="user">The user to generate an email confirmation token for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, an email confirmation token.
        /// </returns>
        public virtual Task<string> GenerateEmailConfirmationTokenAsync(TUser user)
        {
            ThrowIfDisposed();
            return GenerateUserTokenAsync(user, Options.Tokens.EmailConfirmationTokenProvider, ConfirmEmailTokenPurpose);
        }

        /// <summary>
        /// Validates that an email confirmation token matches the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to validate the token against.</param>
        /// <param name="token">The email confirmation token to validate.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> ConfirmEmailAsync(TUser user, string token)
        {
            ThrowIfDisposed();
            var store = GetEmailStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (!await VerifyUserTokenAsync(user, Options.Tokens.EmailConfirmationTokenProvider, ConfirmEmailTokenPurpose, token))
            {
                return IdentityResult.Failed(ErrorDescriber.InvalidToken());
            }
            await store.SetEmailConfirmedAsync(user, true, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Gets a flag indicating whether the email address for the specified <paramref name="user"/> has been verified, true if the email address is verified otherwise
        /// false.
        /// </summary>
        /// <param name="user">The user whose email confirmation status should be returned.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous operation, a flag indicating whether the email address for the specified <paramref name="user"/>
        /// has been confirmed or not.
        /// </returns>
        public virtual async Task<bool> IsEmailConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetEmailStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await store.GetEmailConfirmedAsync(user, CancellationToken);
        }

        /// <summary>
        /// Generates an email change token for the specified user.
        /// </summary>
        /// <param name="user">The user to generate an email change token for.</param>
        /// <param name="newEmail">The new email address.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, an email change token.
        /// </returns>
        public virtual Task<string> GenerateChangeEmailTokenAsync(TUser user, string newEmail)
        {
            ThrowIfDisposed();
            return GenerateUserTokenAsync(user, Options.Tokens.ChangeEmailTokenProvider, GetChangeEmailTokenPurpose(newEmail));
        }

        /// <summary>
        /// Updates a users emails if the specified email change <paramref name="token"/> is valid for the user.
        /// </summary>
        /// <param name="user">The user whose email should be updated.</param>
        /// <param name="newEmail">The new email address.</param>
        /// <param name="token">The change email token to be verified.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> ChangeEmailAsync(TUser user, string newEmail, string token)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // Make sure the token is valid and the stamp matches
            if (!await VerifyUserTokenAsync(user, Options.Tokens.ChangeEmailTokenProvider, GetChangeEmailTokenPurpose(newEmail), token))
            {
                return IdentityResult.Failed(ErrorDescriber.InvalidToken());
            }
            var store = GetEmailStore();
            await store.SetEmailAsync(user, newEmail, CancellationToken);
            await store.SetEmailConfirmedAsync(user, true, CancellationToken);
            await UpdateSecurityStampInternal(user);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Gets the telephone number, if any, for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose telephone number should be retrieved.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the user's telephone number, if any.</returns>
        public virtual async Task<string> GetPhoneNumberAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetPhoneNumberStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await store.GetPhoneNumberAsync(user, CancellationToken);
        }

        /// <summary>
        /// Sets the phone number for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose phone number to set.</param>
        /// <param name="phoneNumber">The phone number to set.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> SetPhoneNumberAsync(TUser user, string phoneNumber)
        {
            ThrowIfDisposed();
            var store = GetPhoneNumberStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await store.SetPhoneNumberAsync(user, phoneNumber, CancellationToken);
            await store.SetPhoneNumberConfirmedAsync(user, false, CancellationToken);
            await UpdateSecurityStampInternal(user);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Sets the phone number for the specified <paramref name="user"/> if the specified
        /// change <paramref name="token"/> is valid.
        /// </summary>
        /// <param name="user">The user whose phone number to set.</param>
        /// <param name="phoneNumber">The phone number to set.</param>
        /// <param name="token">The phone number confirmation token to validate.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/>
        /// of the operation.
        /// </returns>
        public virtual async Task<IdentityResult> ChangePhoneNumberAsync(TUser user, string phoneNumber, string token)
        {
            ThrowIfDisposed();
            var store = GetPhoneNumberStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (!await VerifyChangePhoneNumberTokenAsync(user, token, phoneNumber))
            {
                Logger.LogWarning(7, "Change phone number for user {userId} failed with invalid token.", await GetUserIdAsync(user));
                return IdentityResult.Failed(ErrorDescriber.InvalidToken());
            }
            await store.SetPhoneNumberAsync(user, phoneNumber, CancellationToken);
            await store.SetPhoneNumberConfirmedAsync(user, true, CancellationToken);
            await UpdateSecurityStampInternal(user);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Gets a flag indicating whether the specified <paramref name="user"/>'s telephone number has been confirmed.
        /// </summary>
        /// <param name="user">The user to return a flag for, indicating whether their telephone number is confirmed.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, returning true if the specified <paramref name="user"/> has a confirmed
        /// telephone number otherwise false.
        /// </returns>
        public virtual Task<bool> IsPhoneNumberConfirmedAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetPhoneNumberStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return store.GetPhoneNumberConfirmedAsync(user, CancellationToken);
        }

        /// <summary>
        /// Generates a telephone number change token for the specified user.
        /// </summary>
        /// <param name="user">The user to generate a telephone number token for.</param>
        /// <param name="phoneNumber">The new phone number the validation token should be sent to.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the telephone change number token.
        /// </returns>
        public virtual Task<string> GenerateChangePhoneNumberTokenAsync(TUser user, string phoneNumber)
        {
            ThrowIfDisposed();
            return GenerateUserTokenAsync(user, Options.Tokens.ChangePhoneNumberTokenProvider, ChangePhoneNumberTokenPurpose + ":" + phoneNumber);
        }

        /// <summary>
        /// Returns a flag indicating whether the specified <paramref name="user"/>'s phone number change verification
        /// token is valid for the given <paramref name="phoneNumber"/>.
        /// </summary>
        /// <param name="user">The user to validate the token against.</param>
        /// <param name="token">The telephone number change token to validate.</param>
        /// <param name="phoneNumber">The telephone number the token was generated for.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, returning true if the <paramref name="token"/>
        /// is valid, otherwise false.
        /// </returns>
        public virtual Task<bool> VerifyChangePhoneNumberTokenAsync(TUser user, string token, string phoneNumber)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // Make sure the token is valid and the stamp matches
            return VerifyUserTokenAsync(user, Options.Tokens.ChangePhoneNumberTokenProvider, ChangePhoneNumberTokenPurpose+":"+ phoneNumber, token);
        }

        /// <summary>
        /// Returns a flag indicating whether the specified <paramref name="token"/> is valid for
        /// the given <paramref name="user"/> and <paramref name="purpose"/>.
        /// </summary>
        /// <param name="user">The user to validate the token against.</param>
        /// <param name="tokenProvider">The token provider used to generate the token.</param>
        /// <param name="purpose">The purpose the token should be generated for.</param>
        /// <param name="token">The token to validate</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, returning true if the <paramref name="token"/>
        /// is valid, otherwise false.
        /// </returns>
        public virtual async Task<bool> VerifyUserTokenAsync(TUser user, string tokenProvider, string purpose, string token)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (tokenProvider == null)
            {
                throw new ArgumentNullException(nameof(tokenProvider));
            }

            if (!_tokenProviders.ContainsKey(tokenProvider))
            {
                throw new NotSupportedException(Resources.FormatNoTokenProvider(nameof(TUser), tokenProvider));
            }
            // Make sure the token is valid
            var result = await _tokenProviders[tokenProvider].ValidateAsync(purpose, token, this, user);

            if (!result)
            {
                Logger.LogWarning(9, "VerifyUserTokenAsync() failed with purpose: {purpose} for user {userId}.", purpose, await GetUserIdAsync(user));
            }
            return result;
        }

        /// <summary>
        /// Generates a token for the given <paramref name="user"/> and <paramref name="purpose"/>.
        /// </summary>
        /// <param name="purpose">The purpose the token will be for.</param>
        /// <param name="user">The user the token will be for.</param>
        /// <param name="tokenProvider">The provider which will generate the token.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents result of the asynchronous operation, a token for
        /// the given user and purpose.
        /// </returns>
        public virtual Task<string> GenerateUserTokenAsync(TUser user, string tokenProvider, string purpose)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (tokenProvider == null)
            {
                throw new ArgumentNullException(nameof(tokenProvider));
            }
            if (!_tokenProviders.ContainsKey(tokenProvider))
            {
                throw new NotSupportedException(Resources.FormatNoTokenProvider(nameof(TUser), tokenProvider));
            }

            return _tokenProviders[tokenProvider].GenerateAsync(purpose, this, user);
        }

        /// <summary>
        /// Registers a token provider.
        /// </summary>
        /// <param name="providerName">The name of the provider to register.</param>
        /// <param name="provider">The provider to register.</param>
        public virtual void RegisterTokenProvider(string providerName, IUserTwoFactorTokenProvider<TUser> provider)
        {
            ThrowIfDisposed();
            if (provider == null)
            {
                throw new ArgumentNullException(nameof(provider));
            }
            _tokenProviders[providerName] = provider;
        }

        /// <summary>
        /// Gets a list of valid two factor token providers for the specified <paramref name="user"/>,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user the whose two factor authentication providers will be returned.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents result of the asynchronous operation, a list of two
        /// factor authentication providers for the specified user.
        /// </returns>
        public virtual async Task<IList<string>> GetValidTwoFactorProvidersAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var results = new List<string>();
            foreach (var f in _tokenProviders)
            {
                if (await f.Value.CanGenerateTwoFactorTokenAsync(this, user))
                {
                    results.Add(f.Key);
                }
            }
            return results;
        }

        /// <summary>
        /// Verifies the specified two factor authentication <paramref name="token" /> against the <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user the token is supposed to be for.</param>
        /// <param name="tokenProvider">The provider which will verify the token.</param>
        /// <param name="token">The token to verify.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents result of the asynchronous operation, true if the token is valid,
        /// otherwise false.
        /// </returns>
        public virtual async Task<bool> VerifyTwoFactorTokenAsync(TUser user, string tokenProvider, string token)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (!_tokenProviders.ContainsKey(tokenProvider))
            {
                throw new NotSupportedException(Resources.FormatNoTokenProvider(nameof(TUser), tokenProvider));
            }

            // Make sure the token is valid
            var result = await _tokenProviders[tokenProvider].ValidateAsync("TwoFactor", token, this, user);
            if (!result)
            {
                Logger.LogWarning(10, $"{nameof(VerifyTwoFactorTokenAsync)}() failed for user {await GetUserIdAsync(user)}.");
            }
            return result;
        }

        /// <summary>
        /// Gets a two factor authentication token for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user the token is for.</param>
        /// <param name="tokenProvider">The provider which will generate the token.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents result of the asynchronous operation, a two factor authentication token
        /// for the user.
        /// </returns>
        public virtual Task<string> GenerateTwoFactorTokenAsync(TUser user, string tokenProvider)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (!_tokenProviders.ContainsKey(tokenProvider))
            {
                throw new NotSupportedException(Resources.FormatNoTokenProvider(nameof(TUser), tokenProvider));
            }

            return _tokenProviders[tokenProvider].GenerateAsync("TwoFactor", this, user);
        }

        /// <summary>
        /// Returns a flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled or not,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose two factor authentication enabled status should be retrieved.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, true if the specified <paramref name="user "/>
        /// has two factor authentication enabled, otherwise false.
        /// </returns>
        public virtual async Task<bool> GetTwoFactorEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetUserTwoFactorStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await store.GetTwoFactorEnabledAsync(user, CancellationToken);
        }

        /// <summary>
        /// Sets a flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled or not,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose two factor authentication enabled status should be set.</param>
        /// <param name="enabled">A flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, the <see cref="IdentityResult"/> of the operation
        /// </returns>
        public virtual async Task<IdentityResult> SetTwoFactorEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            var store = GetUserTwoFactorStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await store.SetTwoFactorEnabledAsync(user, enabled, CancellationToken);
            await UpdateSecurityStampInternal(user);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Returns a flag indicating whether the specified <paramref name="user"/> his locked out,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose locked out status should be retrieved.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, true if the specified <paramref name="user "/>
        /// is locked out, otherwise false.
        /// </returns>
        public virtual async Task<bool> IsLockedOutAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (!await store.GetLockoutEnabledAsync(user, CancellationToken))
            {
                return false;
            }
            var lockoutTime = await store.GetLockoutEndDateAsync(user, CancellationToken);
            return lockoutTime >= DateTimeOffset.UtcNow;
        }

        /// <summary>
        /// Sets a flag indicating whether the specified <paramref name="user"/> is locked out,
        /// as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose locked out status should be set.</param>
        /// <param name="enabled">Flag indicating whether the user is locked out or not.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, the <see cref="IdentityResult"/> of the operation
        /// </returns>
        public virtual async Task<IdentityResult> SetLockoutEnabledAsync(TUser user, bool enabled)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            await store.SetLockoutEnabledAsync(user, enabled, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Retrieves a flag indicating whether user lockout can be enabled for the specified user.
        /// </summary>
        /// <param name="user">The user whose ability to be locked out should be returned.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, true if a user can be locked out, otherwise false.
        /// </returns>
        public virtual async Task<bool> GetLockoutEnabledAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await store.GetLockoutEnabledAsync(user, CancellationToken);
        }

        /// <summary>
        /// Gets the last <see cref="DateTimeOffset"/> a user's last lockout expired, if any.
        /// A time value in the past indicates a user is not currently locked out.
        /// </summary>
        /// <param name="user">The user whose lockout date should be retrieved.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the lookup, a <see cref="DateTimeOffset"/> containing the last time a user's lockout expired, if any.
        /// </returns>
        public virtual async Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await store.GetLockoutEndDateAsync(user, CancellationToken);
        }

        /// <summary>
        /// Locks out a user until the specified end date has passed. Setting a end date in the past immediately unlocks a user.
        /// </summary>
        /// <param name="user">The user whose lockout date should be set.</param>
        /// <param name="lockoutEnd">The <see cref="DateTimeOffset"/> after which the <paramref name="user"/>'s lockout should end.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the operation.</returns>
        public virtual async Task<IdentityResult> SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (!await store.GetLockoutEnabledAsync(user, CancellationToken))
            {
                Logger.LogWarning(11, "Lockout for user {userId} failed because lockout is not enabled for this user.", await GetUserIdAsync(user));
                return IdentityResult.Failed(ErrorDescriber.UserLockoutNotEnabled());
            }
            await store.SetLockoutEndDateAsync(user, lockoutEnd, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Increments the access failed count for the user as an asynchronous operation.
        /// If the failed access account is greater than or equal to the configured maximum number of attempts,
        /// the user will be locked out for the configured lockout time span.
        /// </summary>
        /// <param name="user">The user whose failed access count to increment.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the operation.</returns>
        public virtual async Task<IdentityResult> AccessFailedAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            // If this puts the user over the threshold for lockout, lock them out and reset the access failed count
            var count = await store.IncrementAccessFailedCountAsync(user, CancellationToken);
            if (count < Options.Lockout.MaxFailedAccessAttempts)
            {
                return await UpdateUserAsync(user);
            }
            Logger.LogWarning(12, "User {userId} is locked out.", await GetUserIdAsync(user));
            await store.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.Add(Options.Lockout.DefaultLockoutTimeSpan),
                CancellationToken);
            await store.ResetAccessFailedCountAsync(user, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Resets the access failed count for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose failed access count should be reset.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the operation.</returns>
        public virtual async Task<IdentityResult> ResetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (await GetAccessFailedCountAsync(user) == 0)
            {
                return IdentityResult.Success;
            }
            await store.ResetAccessFailedCountAsync(user, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Retrieves the current number of failed accesses for the given <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose access failed count should be retrieved for.</param>
        /// <returns>The <see cref="Task"/> that contains the result the asynchronous operation, the current failed access count
        /// for the user.</returns>
        public virtual async Task<int> GetAccessFailedCountAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetUserLockoutStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return await store.GetAccessFailedCountAsync(user, CancellationToken);
        }

        /// <summary>
        /// Returns a list of users from the user store who have the specified <paramref name="claim"/>.
        /// </summary>
        /// <param name="claim">The claim to look for.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <typeparamref name="TUser"/>s who
        /// have the specified claim.
        /// </returns>
        public virtual Task<IList<TUser>> GetUsersForClaimAsync(Claim claim)
        {
            ThrowIfDisposed();
            var store = GetClaimStore();
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            return store.GetUsersForClaimAsync(claim, CancellationToken);
        }

        /// <summary>
        /// Returns a list of users from the user store who are members of the specified <paramref name="roleName"/>.
        /// </summary>
        /// <param name="roleName">The name of the role whose users should be returned.</param>
        /// <returns>
        /// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a list of <typeparamref name="TUser"/>s who
        /// are members of the specified role.
        /// </returns>
        public virtual Task<IList<TUser>> GetUsersInRoleAsync(string roleName)
        {
            ThrowIfDisposed();
            var store = GetUserRoleStore();
            if (roleName == null)
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            return store.GetUsersInRoleAsync(NormalizeName(roleName), CancellationToken);
        }

        /// <summary>
        /// Returns an authentication token for a user.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="loginProvider">The authentication scheme for the provider the token is associated with.</param>
        /// <param name="tokenName">The name of the token.</param>
        /// <returns>The authentication token for a user</returns>
        public virtual Task<string> GetAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName)
        {
            ThrowIfDisposed();
            var store = GetAuthenticationTokenStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }
            if (tokenName == null)
            {
                throw new ArgumentNullException(nameof(tokenName));
            }

            return store.GetTokenAsync(user, loginProvider, tokenName, CancellationToken);
        }

        /// <summary>
        /// Sets an authentication token for a user.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="loginProvider">The authentication scheme for the provider the token is associated with.</param>
        /// <param name="tokenName">The name of the token.</param>
        /// <param name="tokenValue">The value of the token.</param>
        /// <returns>Whether the user was successfully updated.</returns>
        public virtual async Task<IdentityResult> SetAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName, string tokenValue)
        {
            ThrowIfDisposed();
            var store = GetAuthenticationTokenStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }
            if (tokenName == null)
            {
                throw new ArgumentNullException(nameof(tokenName));
            }

            // REVIEW: should updating any tokens affect the security stamp?
            await store.SetTokenAsync(user, loginProvider, tokenName, tokenValue, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Remove an authentication token for a user.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="loginProvider">The authentication scheme for the provider the token is associated with.</param>
        /// <param name="tokenName">The name of the token.</param>
        /// <returns>Whether a token was removed.</returns>
        public virtual async Task<IdentityResult> RemoveAuthenticationTokenAsync(TUser user, string loginProvider, string tokenName)
        {
            ThrowIfDisposed();
            var store = GetAuthenticationTokenStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }
            if (tokenName == null)
            {
                throw new ArgumentNullException(nameof(tokenName));
            }

            await store.RemoveTokenAsync(user, loginProvider, tokenName, CancellationToken);
            return await UpdateUserAsync(user);
        }

        /// <summary>
        /// Returns the authenticator key for the user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>The authenticator key</returns>
        public virtual Task<string> GetAuthenticatorKeyAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetAuthenticatorKeyStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return store.GetAuthenticatorKeyAsync(user, CancellationToken);
        }

        /// <summary>
        /// Resets the authenticator key for the user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>Whether the user was successfully updated.</returns>
        public virtual async Task<IdentityResult> ResetAuthenticatorKeyAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetAuthenticatorKeyStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            await store.SetAuthenticatorKeyAsync(user, GenerateNewAuthenticatorKey(), CancellationToken);
            await UpdateSecurityStampInternal(user);
            return await UpdateAsync(user);
        }

        /// <summary>
        /// Generates a new base32 encoded 160-bit security secret (size of SHA1 hash).
        /// </summary>
        /// <returns>The new security secret.</returns>
        public virtual string GenerateNewAuthenticatorKey()
            => NewSecurityStamp();

        /// <summary>
        /// Generates recovery codes for the user, this invalidates any previous recovery codes for the user.
        /// </summary>
        /// <param name="user">The user to generate recovery codes for.</param>
        /// <param name="number">The number of codes to generate.</param>
        /// <returns>The new recovery codes for the user.  Note: there may be less than number returned, as duplicates will be removed.</returns>
        public virtual async Task<IEnumerable<string>> GenerateNewTwoFactorRecoveryCodesAsync(TUser user, int number)
        {
            ThrowIfDisposed();
            var store = GetRecoveryCodeStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var newCodes = new List<string>(number);
            for (var i = 0; i < number; i++)
            {
                newCodes.Add(CreateTwoFactorRecoveryCode());
            }

            await store.ReplaceCodesAsync(user, newCodes.Distinct(), CancellationToken);
            var update = await UpdateAsync(user);
            if (update.Succeeded)
            {
                return newCodes;
            }
            return null;
        }

        /// <summary>
        /// Generate a new recovery code.
        /// </summary>
        /// <returns></returns>
        protected virtual string CreateTwoFactorRecoveryCode()
            => Guid.NewGuid().ToString().Substring(0, 8);

        /// <summary>
        /// Returns whether a recovery code is valid for a user. Note: recovery codes are only valid
        /// once, and will be invalid after use.
        /// </summary>
        /// <param name="user">The user who owns the recovery code.</param>
        /// <param name="code">The recovery code to use.</param>
        /// <returns>True if the recovery code was found for the user.</returns>
        public virtual async Task<IdentityResult> RedeemTwoFactorRecoveryCodeAsync(TUser user, string code)
        {
            ThrowIfDisposed();
            var store = GetRecoveryCodeStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var success = await store.RedeemCodeAsync(user, code, CancellationToken);
            if (success)
            {
                return await UpdateAsync(user);
            }
            return IdentityResult.Failed(ErrorDescriber.RecoveryCodeRedemptionFailed());
        }

        /// <summary>
        /// Returns how many recovery code are still valid for a user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>How many recovery code are still valid for a user.</returns>
        public virtual Task<int> CountRecoveryCodesAsync(TUser user)
        {
            ThrowIfDisposed();
            var store = GetRecoveryCodeStore();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return store.CountCodesAsync(user, CancellationToken);
        }

        /// <summary>
        /// Releases the unmanaged resources used by the role manager and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                Store.Dispose();
                _disposed = true;
            }
        }

        private IUserTwoFactorStore<TUser> GetUserTwoFactorStore()
        {
            var cast = Store as IUserTwoFactorStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserTwoFactorStore);
            }
            return cast;
        }

        private IUserLockoutStore<TUser> GetUserLockoutStore()
        {
            var cast = Store as IUserLockoutStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserLockoutStore);
            }
            return cast;
        }

        private IUserEmailStore<TUser> GetEmailStore(bool throwOnFail = true)
        {
            var cast = Store as IUserEmailStore<TUser>;
            if (throwOnFail && cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserEmailStore);
            }
            return cast;
        }

        private IUserPhoneNumberStore<TUser> GetPhoneNumberStore()
        {
            var cast = Store as IUserPhoneNumberStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserPhoneNumberStore);
            }
            return cast;
        }

        /// <summary>
        /// Creates bytes to use as a security token from the user's security stamp.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>The security token bytes.</returns>
        public virtual async Task<byte[]> CreateSecurityTokenAsync(TUser user)
        {
            return Encoding.Unicode.GetBytes(await GetSecurityStampAsync(user));
        }

        // Update the security stamp if the store supports it
        private async Task UpdateSecurityStampInternal(TUser user)
        {
            if (SupportsUserSecurityStamp)
            {
                await GetSecurityStore().SetSecurityStampAsync(user, NewSecurityStamp(), CancellationToken);
            }
        }

        /// <summary>
        /// Updates a user's password hash.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="newPassword">The new password.</param>
        /// <param name="validatePassword">Whether to validate the password.</param>
        /// <returns>Whether the password has was successfully updated.</returns>
        protected virtual Task<IdentityResult> UpdatePasswordHash(TUser user, string newPassword, bool validatePassword)
            => UpdatePasswordHash(GetPasswordStore(), user, newPassword, validatePassword);

        private async Task<IdentityResult> UpdatePasswordHash(IUserPasswordStore<TUser> passwordStore,
            TUser user, string newPassword, bool validatePassword = true)
        {
            if (validatePassword)
            {
                var validate = await ValidatePasswordAsync(user, newPassword);
                if (!validate.Succeeded)
                {
                    return validate;
                }
            }
            var hash = newPassword != null ? PasswordHasher.HashPassword(user, newPassword) : null;
            await passwordStore.SetPasswordHashAsync(user, hash, CancellationToken);
            await UpdateSecurityStampInternal(user);
            return IdentityResult.Success;
        }

        private IUserRoleStore<TUser> GetUserRoleStore()
        {
            var cast = Store as IUserRoleStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserRoleStore);
            }
            return cast;
        }

        private static string NewSecurityStamp()
        {
            byte[] bytes = new byte[20];
            _rng.GetBytes(bytes);
            return Base32.ToBase32(bytes);
        }

        // IUserLoginStore methods
        private IUserLoginStore<TUser> GetLoginStore()
        {
            var cast = Store as IUserLoginStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserLoginStore);
            }
            return cast;
        }

        private IUserSecurityStampStore<TUser> GetSecurityStore()
        {
            var cast = Store as IUserSecurityStampStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserSecurityStampStore);
            }
            return cast;
        }

        private IUserClaimStore<TUser> GetClaimStore()
        {
            var cast = Store as IUserClaimStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserClaimStore);
            }
            return cast;
        }


        /// <summary>
        /// Generates the token purpose used to change email.
        /// </summary>
        /// <param name="newEmail">The new email address.</param>
        /// <returns>The token purpose.</returns>
        protected static string GetChangeEmailTokenPurpose(string newEmail)
        {
            return "ChangeEmail:" + newEmail;
        }

        /// <summary>
        /// Should return <see cref="IdentityResult.Success"/> if validation is successful. This is
        /// called before saving the user via Create or Update.
        /// </summary>
        /// <param name="user">The user</param>
        /// <returns>A <see cref="IdentityResult"/> representing whether validation was successful.</returns>
        protected async Task<IdentityResult> ValidateUserAsync(TUser user)
        {
            if (SupportsUserSecurityStamp)
            {
                var stamp = await GetSecurityStampAsync(user);
                if (stamp == null)
                {
                    throw new InvalidOperationException(Resources.NullSecurityStamp);
                }
            }
            var errors = new List<IdentityError>();
            foreach (var v in UserValidators)
            {
                var result = await v.ValidateAsync(this, user);
                if (!result.Succeeded)
                {
                    errors.AddRange(result.Errors);
                }
            }
            if (errors.Count > 0)
            {
                Logger.LogWarning(13, "User {userId} validation failed: {errors}.", await GetUserIdAsync(user), string.Join(";", errors.Select(e => e.Code)));
                return IdentityResult.Failed(errors.ToArray());
            }
            return IdentityResult.Success;
        }

        /// <summary>
        /// Should return <see cref="IdentityResult.Success"/> if validation is successful. This is
        /// called before updating the password hash.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="password">The password.</param>
        /// <returns>A <see cref="IdentityResult"/> representing whether validation was successful.</returns>
        protected async Task<IdentityResult> ValidatePasswordAsync(TUser user, string password)
        {
            var errors = new List<IdentityError>();
            var isValid = true;
            foreach (var v in PasswordValidators)
            {
                var result = await v.ValidateAsync(this, user, password);
                if (!result.Succeeded)
                {
                    if (result.Errors.Any())
                    {
                        errors.AddRange(result.Errors);
                    }

                    isValid = false;
                }
            }
            if (!isValid)
            {
                Logger.LogWarning(14, "User {userId} password validation failed: {errors}.", await GetUserIdAsync(user), string.Join(";", errors.Select(e => e.Code)));
                return IdentityResult.Failed(errors.ToArray());
            }
            return IdentityResult.Success;
        }

        /// <summary>
        /// Called to update the user after validating and updating the normalized email/user name.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>Whether the operation was successful.</returns>
        protected virtual async Task<IdentityResult> UpdateUserAsync(TUser user)
        {
            var result = await ValidateUserAsync(user);
            if (!result.Succeeded)
            {
                return result;
            }
            await UpdateNormalizedUserNameAsync(user);
            await UpdateNormalizedEmailAsync(user);
            return await Store.UpdateAsync(user, CancellationToken);
        }

        private IUserAuthenticatorKeyStore<TUser> GetAuthenticatorKeyStore()
        {
            var cast = Store as IUserAuthenticatorKeyStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserAuthenticatorKeyStore);
            }
            return cast;
        }

        private IUserTwoFactorRecoveryCodeStore<TUser> GetRecoveryCodeStore()
        {
            var cast = Store as IUserTwoFactorRecoveryCodeStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserTwoFactorRecoveryCodeStore);
            }
            return cast;
        }

        private IUserAuthenticationTokenStore<TUser> GetAuthenticationTokenStore()
        {
            var cast = Store as IUserAuthenticationTokenStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserAuthenticationTokenStore);
            }
            return cast;
        }

        private IUserPasswordStore<TUser> GetPasswordStore()
        {
            var cast = Store as IUserPasswordStore<TUser>;
            if (cast == null)
            {
                throw new NotSupportedException(Resources.StoreNotIUserPasswordStore);
            }
            return cast;
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

    }
```
### UserOptions
```
    /// <summary>
    /// 用户验证的选项。
    /// </summary>
    public class UserOptions
    {
        /// <summary>
        /// 获取或设置用于验证用户名的用户名中允许的字符列表。 默认为abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+
        /// </summary>
        /// <value>
        /// The list of allowed characters in the username used to validate user names.
        /// </value>
        public string AllowedUserNameCharacters { get; set; } = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";

        /// <summary>
        /// 获取或设置应用程序的标志，要求其用户使用唯一的电子邮件。 默认为false。
        /// </summary>
        /// <value>
        /// True if the application requires each user to have their own, unique email, otherwise false.
        /// </value>
        public bool RequireUniqueEmail { get; set; }
    }
```