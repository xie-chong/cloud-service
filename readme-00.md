# <p align="center">随笔</p>

- [04.7 多账户-用户凭证表](#04.7)   
- [04.8 放开某url的权限](#04.8)   
- [05.1 认证中心代码结构](#05.1)   
- [05.2 FeignClient简单介绍](#05.2)   
- [05.3 认证中心配置类和接口](#05.3)   
- [05.4 登陆和鉴权](#05.4)   
- [05.5 生成 access_token 的核心源码](#05.5)   
- [05.6 根据 access_token 获取当前用户的核心源码](#05.6)   
- [05.7 认证中心获取当前登陆用户核心代码](#05.7)   
- [05.8 别的微服务获取当前登陆用户核心代码](#05.8)   
- [05.9 redis 缓存 oauth2 中的 client 信息](#05.9)   
- [06.1 网关 zuul](#06.1)   
- [06.2 网关端口说明](#06.2)   
- [07.1 日志中心讲解](#07.1)   
- [07.2 日志组件 aop 实现](#07.2)   











## 1

org\springframework\security\crypto\bcrypt\BCryptPasswordEncoder.class    
```
public class BCryptPasswordEncoder implements PasswordEncoder {
```
该类提供了密码加密、密码匹配等方法。

## 2

用户修改密码和后台管理员修改密码是两个不同的request url，后者有权限控制。
```
  /**
     * 修改密码
     *
     * @param oldPassword 旧密码
     * @param newPassword 新密码
     */
    @LogAnnotation(module = "修改密码")
    @PutMapping(value = "/users/password", params = {"oldPassword", "newPassword"})
    public void updatePassword(String oldPassword, String newPassword) {
        if (StringUtils.isBlank(oldPassword)) {
            throw new IllegalArgumentException("旧密码不能为空");
        }
        if (StringUtils.isBlank(newPassword)) {
            throw new IllegalArgumentException("新密码不能为空");
        }

        AppUser user = AppUserUtil.getLoginAppUser();
        appUserService.updatePassword(user.getId(), oldPassword, newPassword);
    }

    /**
     * 管理后台，给用户重置密码
     *
     * @param id          用户id
     * @param newPassword 新密码
     */
    @LogAnnotation(module = "重置密码")
    @PreAuthorize("hasAuthority('back:user:password')")
    @PutMapping(value = "/users/{id}/password", params = {"newPassword"})
    public void resetPassword(@PathVariable Long id, String newPassword) {
        appUserService.updatePassword(id, null, newPassword);
    }
```

## 3

给用户设置角色 ，采用先删除老角色，再插入新角色。


## 4
```
/**
	 * 给角色设置权限
	 *
	 * @param roleId
	 * @param permissionIds
	 */
	@Transactional
	@Override
	public void setPermissionToRole(Long roleId, Set<Long> permissionIds) {
		SysRole sysRole = sysRoleDao.findById(roleId);
		if (sysRole == null) {
			throw new IllegalArgumentException("角色不存在");
		}

		// 查出角色对应的old权限
		Set<Long> oldPermissionIds = rolePermissionDao.findPermissionsByRoleIds(Sets.newHashSet(roleId)).stream()
				.map(p -> p.getId()).collect(Collectors.toSet());

		// 需要添加的权限
		Collection<Long> addPermissionIds = org.apache.commons.collections4.CollectionUtils.subtract(permissionIds,
				oldPermissionIds);
		if (!CollectionUtils.isEmpty(addPermissionIds)) {
			addPermissionIds.forEach(permissionId -> {
				rolePermissionDao.saveRolePermission(roleId, permissionId);
			});
		}
		// 需要移除的权限
		Collection<Long> deletePermissionIds = org.apache.commons.collections4.CollectionUtils
				.subtract(oldPermissionIds, permissionIds);
		if (!CollectionUtils.isEmpty(deletePermissionIds)) {
			deletePermissionIds.forEach(permissionId -> {
				rolePermissionDao.deleteRolePermission(roleId, permissionId);
			});
		}

		log.info("给角色id：{}，分配权限：{}", roleId, permissionIds);
	}
```

其逻辑与把全部权限删除，再插入新的权限效果一样。

demo:
```
	public static void main(String[] args) {
		Set<String> oldP = new HashSet();
		oldP.add("a");
		oldP.add("b");
		oldP.add("c");

		Set<String> newP = new HashSet();
		newP.add("c");
		newP.add("d");
		newP.add("e");

		ArrayList<String> s1 = (ArrayList<String>) org.apache.commons.collections4.CollectionUtils.subtract(newP,oldP);

		ArrayList<String> s2 = (ArrayList<String>) org.apache.commons.collections4.CollectionUtils.subtract(oldP,newP);

		System.out.println(oldP);
		System.out.println(newP);
		System.out.println(s1);
		System.out.println(s2);

	}/*
	out:
	[a, b, c]
	[c, d, e]
	[d, e]
	[a, b]	
	*/
  
```








---
<h2 id="04.7">04.7 多账户-用户凭证表</h2>

---

当系统支持多种类型登陆时（手机号、用户名、微信号），我们可以创建一张用户凭证表，以便在同一个用户id下支持多种登陆类型。

table:user_credentials

| username | type | userid |
| :---- | :---- | :---- |
| admin | USERNAME | 1 |
| 13247610000 | USERNAME | 1 |
| superadmin | USERNAME | 2 |

```
select u.* from app_user u inner join user_credentials c on c.userId = u.id where c.username = '13247610000';
```






---
<h2 id="04.8">04.8 放开某url的权限</h2>

---

除了认证中心 oauth-center 需要配置两个地方（ResourceServerConfig.java、SecurityConfig.java），其他服务只需要配置一个地方（ResourceServerConfig.java）。

放开权限的url可以不带access-token，如果携带则需要保证其正确性，否则会提示401错误。
```
/**  资源服务配置 */
@EnableResourceServer
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

// ......
.antMatchers(PermitAllUrl.permitAllUrl("/users-anon/**", "/wechat/**")).permitAll() // 放开权限的url

// ......
}
```

```
/** spring security配置 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
// ......
	/**
	 * http安全配置
	 * @param http
	 *            http安全对象
	 * @throws Exception
	 *             http安全异常信息
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers(PermitAllUrl.permitAllUrl()).permitAll() // 放开权限的url
				.anyRequest().authenticated().and()
				.httpBasic().and().csrf().disable();
	}
}
```






---
<h2 id="05.1">05.1 认证中心代码结构</h2>

---

cloud-service\config-center\src\main\resources\configs\dev\oauth-center.yml中
```
ribbon:
  eager-load:
    enabled: true  # 开启Ribbon的饥饿加载模式
    clients: user-center  # 指定需要饥饿加载的服务名
```
* 该配置为 **true** 时 oauth-center 启动时从注册中心获取 user-center 的IP和port
* 该配置为 **false** 时 oauth-center 第一次调用 user-center 时获取 user-center 的IP和port

Ribbon进行客户端负载均衡的Client并不是在服务启动的时候就初始化好的，而是在调用的时候才会去创建相应的Client，所以第一次调用的耗时不仅仅包含发送HTTP请求的时间，还包含了创建RibbonClient的时间，这样一来如果创建时间速度较慢，同时设置的超时时间又比较短的话，很容易就会出现在服务都成功启动的时候第一次访问会有报错的情况发生,但是之后又恢复正常访问。

因此我们可以通过设置，**开启Ribbon的饥饿加载模式**







---
<h2 id="05.2">05.2 FeignClient简单介绍</h2>

---

cloud-service\oauth-center\src\main\java\com\cloud\oauth\OAuthCenterApplication.java
```
/** 认证中心 */
@EnableFeignClients
@EnableDiscoveryClient
@SpringBootApplication
public class OAuthCenterApplication {

	public static void main(String[] args) {
		SpringApplication.run(OAuthCenterApplication.class, args);
	}
}
```

cloud-service\oauth-center\src\main\java\com\cloud\oauth\feign\UserClient.java
```
@FeignClient("user-center")//该参数为对应的 spring.application.name: user-center
public interface UserClient {

    @GetMapping(value = "/users-anon/internal", params = "username")
    LoginAppUser findByUsername(@RequestParam("username") String username);

    @GetMapping("/wechat/login-check")
    public void wechatLoginCheck(@RequestParam("tempCode") String tempCode, @RequestParam("openid") String openid);
}
```

cloud-service\user-center\src\main\java\com\cloud\user\controller\UserController.java
```
@Slf4j
@RestController
public class UserController {

    // ......

    @GetMapping(value = "/users-anon/internal", params = "username")
    public LoginAppUser findByUsername(String username) {
        return appUserService.findByUsername(username);
    }

    // ......
}
```

UserClient.java中的请求和UserController.java对应保持一致（类似MVC），返回类型可以不相同，但 @FeignClient 中的请求参数必须要有注解 @RequestParam。

若包含@PathVariable，则其属性名不能为空，否则会报错
```
    // 错误
//    @PreAuthorize("hasAuthority('back:user:query')")
//    @GetMapping("/users/{id}")
//    public AppUser findUserById(@PathVariable Long id) {
//        return appUserService.findById(id);
//    }

    @PreAuthorize("hasAuthority('back:user:query')")
    @GetMapping("/users/{id}")
    public AppUser findUserById(@PathVariable("id") Long id) {
        return appUserService.findById(id);
    }
```

**使用**
```
@FeignClient("user-center")
public interface UserClient {
```
UserClient.java 可以作为一个javaBean来注入使用，调用其方法就可以把请求发送到对应的服务。就避免我们自己主动发起 RESTFUL 请求。
```
@Slf4j
@Service("userDetailsService")
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private UserClient userClient;
	// ......
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 为了支持多类型登录，这里username后面拼装上登录类型,如username|type
        String[] params = username.split("\\|");
        username = params[0];// 真正的用户名

        LoginAppUser loginAppUser = userClient.findByUsername(username);

// ......
```






---
<h2 id="05.3">05.3 认证中心配置类和接口</h2>

---

### 认证中心 oauth-center 是一个授权服务器

cloud-service\oauth-center\src\main\java\com\cloud\oauth\config\AuthorizationServerConfig.java

* 注解 @EnableAuthorizationServer
* 继承 AuthorizationServerConfigurerAdapter

```
/** 授权服务器配置 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
```

### 认证中心 oauth-center 是一个资源服务器

cloud-service\oauth-center\src\main\java\com\cloud\oauth\config\ResourceServerConfig.java

```
/**
 * 资源服务配置<br>
 *
 * 注解@EnableResourceServer帮我们加入了org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter<br>
 * 该filter帮我们从request里解析出access_token<br>
 * 并通过org.springframework.security.oauth2.provider.token.DefaultTokenServices根据access_token和认证服务器配置里的TokenStore从redis或者jwt里解析出用户
 *
 * 注意认证中心的@EnableResourceServer和别的微服务里的@EnableResourceServer有些不同<br>
 * 别的微服务是通过org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices来获取用户的
 *
 *
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

```

### 用户校验

cloud-service\oauth-center\src\main\java\com\cloud\oauth\config\SecurityConfig.java

### 开启session共享
cloud-service\oauth-center\src\main\java\com\cloud\oauth\config\SessionConfig.java

引入依赖，借助redis来实现session共享（注意不能省略注解 @EnableRedisHttpSession），当请求过来，系统会自动把session存储到redis。

```
		<dependency>
			<groupId>org.springframework.session</groupId>
			<artifactId>spring-session-data-redis</artifactId>
		</dependency>
```

```
/** 开启session共享 */
@EnableRedisHttpSession
public class SessionConfig {

}
```

### 获取登陆用户

cloud-service\oauth-center\src\main\java\com\cloud\oauth\controller\OAuth2Controller.java

```
@Slf4j
@RestController
@RequestMapping
public class OAuth2Controller {

    /**
     * 当前登陆用户信息<br>
     * <p>
     * security获取当前登录用户的方法是SecurityContextHolder.getContext().getAuthentication()<br>
     * 返回值是接口org.springframework.security.core.Authentication，又继承了Principal<br>
     * 这里的实现类是org.springframework.security.oauth2.provider.OAuth2Authentication<br>
     * <p>
     * 因此这只是一种写法，下面注释掉的三个方法也都一样，这四个方法任选其一即可，也只能选一个，毕竟uri相同，否则启动报错<br>
     * 2018.05.23改为默认用这个方法，好理解一点
     *
     * @return
     */
    @GetMapping("/user-me")
    public Authentication principal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.debug("user-me:{}", authentication.getName());
        return authentication;
    }
// ......
```

与cloud-service\config-center\src\main\resources\configs\dev\user-center.yml对应
```
security:
  oauth2:
    resource:
      user-info-uri: http://local.gateway.com:8080/api-o/user-me
      prefer-token-info: false
```

### 用户退出

cloud-service\oauth-center\src\main\java\com\cloud\oauth\controller\OAuth2Controller.java

```
 @Autowired
    private ConsumerTokenServices tokenServices;

    /**
     * 注销登陆/退出
     * 移除access_token和refresh_token<br>
     * 用ConsumerTokenServices，该接口的实现类DefaultTokenServices已有相关实现
     *
     * @param access_token
     */
    @DeleteMapping(value = "/remove_token", params = "access_token")
    public void removeToken(String access_token) {
        boolean flag = tokenServices.revokeToken(access_token);
        if (flag) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            saveLogoutLog(authentication.getName());
        }
    }
```






---
<h2 id="05.4">05.4 登陆和鉴权</h2>

---

[UML-AbstractUserDetailsAuthenticationProvider](https://github.com/xie-chong/cloud-service/issues/3)

登陆入口 TokenEndpoint.class 里的post方法，根据用户名获取用户信息在 UserDetailServiceImpl.java,密码相关大的配置在 SecurityConfig.java ，密码校验在 AbstractUserDetailsAuthenticationProvider.class、DaoAuthenticationProvider.class

org\springframework\security\oauth2\provider\endpoint\TokenEndpoint.class
```
@FrameworkEndpoint
public class TokenEndpoint extends AbstractEndpoint {
// ......

    @RequestMapping(
        value = {"/oauth/token"},
        method = {RequestMethod.GET}
    )
    public ResponseEntity<OAuth2AccessToken> getAccessToken(Principal principal, @RequestParam Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
        if (!this.allowedRequestMethods.contains(HttpMethod.GET)) {
            throw new HttpRequestMethodNotSupportedException("GET");
        } else {
            return this.postAccessToken(principal, parameters);
        }
    }

    @RequestMapping(
        value = {"/oauth/token"},
        method = {RequestMethod.POST}
    )
    public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal, @RequestParam Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
// ......
```

其中 OAuth2AccessToken 用户名密码模式的登陆即发起post请求。




**test**

1. 修改 bootstrap.yml 里配置的端口为固定值 user-center 7777， oauth-center 8888
2. 修改请求地址 security.oauth2.resource.user-info-uri ，改为 http://localhost:8888/user-me

cloud-service\config-center\src\main\resources\configs\dev\user-center.yml
```
security:
  oauth2:
    resource:
      # user-info-uri: http://local.gateway.com:8080/api-o/user-me
	  # 为了演示，直接配置成认证中心的地址
	  user-info-uri: http://localhost:8888/user-me
      prefer-token-info: false
```
**对应**
cloud-service\oauth-center\src\main\java\com\cloud\oauth\controller\OAuth2Controller.java
```
@Slf4j
@RestController
@RequestMapping
public class OAuth2Controller {

    /**
     * 当前登陆用户信息<br>
     * <p>
     * security获取当前登录用户的方法是SecurityContextHolder.getContext().getAuthentication()<br>
     * 返回值是接口org.springframework.security.core.Authentication，又继承了Principal<br>
     * 这里的实现类是org.springframework.security.oauth2.provider.OAuth2Authentication<br>
     * <p>
     * 因此这只是一种写法，下面注释掉的三个方法也都一样，这四个方法任选其一即可，也只能选一个，毕竟uri相同，否则启动报错<br>
     * 2018.05.23改为默认用这个方法，好理解一点
     *
     * @return
     */
    @GetMapping("/user-me")
    public Authentication principal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.debug("user-me:{}", authentication.getName());
        return authentication;
    }
```
3. 启动 register-center、config-center、oauth-center、user-center

| Application | AMis | AvailablityZones | Status|
| :---- | :---- | :---- | :---- |
| register-center | n/a(1) | (1) | UP(1) xxx |
| config-center | n/a(1) | (1) | UP(1) xxx |
| oauth-center | n/a(1) | (1) | UP(1) xxx |
| user-center | n/a(1) | (1) | UP(1) xxx |

4. 真正的登陆入口 org\springframework\security\oauth2\provider\endpoint\TokenEndpoint.class
```
    @RequestMapping(
        value = {"/oauth/token"},
        method = {RequestMethod.POST}
    )
    public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal, @RequestParam Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
```
可以使用POST请求来测试

REQUEST：
http://localhost:8888/oauth/token?grant_type=password&client_id=system&client_secret=system&scope=app&username=admin&password=admin

参数对应表```select * from oauth_client_details;```

RESPONSE:
```
{
    "access_token": "0cf23b5f-912f-46c4-9fd0-5402398b0f7f",
    "token_type": "bearer",
    "refresh_token": "d33f351a-2eae-419f-a674-732209d75834",
    "expires_in": 28799,
    "scope": "app"
}
```

* **access_token**： 登陆之后返回给前端的一个登陆凭证，前端以后访问别的接口，带上它，就相当于登陆了。我们采用的时redis的uuid，没有使用JWT，可以在oauth-center.yml中配置。
* **token_type**： bearer
* **refresh_token**： 因为 access_token 有过期时间，需要通过它来重新获取access_token,避免重新登陆。对应表字段 oauth_client_details.refresh_token_validity
* **expires_in**： access_token 过期时间，access_token,对应表字段 oauth_client_details.access_token_validity
* **scope**： app"

redis 中存储的内容
```
127.0.0.1:6379> get refresh_to_access:d33f351a-2eae-419f-a674-732209d75834
"0cf23b5f-912f-46c4-9fd0-5402398b0f7f"

```

5. 认证中心的登陆核心

核心 cloud-service\oauth-center\src\main\java\com\cloud\oauth\service\impl\UserDetailServiceImpl.java
```
@Slf4j
@Service("userDetailsService")
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private UserClient userClient;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// 用户中心查询
        LoginAppUser loginAppUser = userClient.findByUsername(username);
        if (loginAppUser == null) {
            throw new AuthenticationCredentialsNotFoundException("用户不存在");
        } else if (!loginAppUser.isEnabled()) {
            throw new DisabledException("用户已作废");
        }
        return loginAppUser;
    }
}
```

密码校验是由 spring-security 框架完成的，在配置类中我们指定了一些自己的实现。

cloud-service\oauth-center\src\main\java\com\cloud\oauth\config\SecurityConfig.java
```
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	public UserDetailsService userDetailsService;
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@Autowired
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
	}
// ......
```

org\springframework\security\authentication\dao\AbstractUserDetailsAuthenticationProvider.class
```
public abstract class AbstractUserDetailsAuthenticationProvider implements AuthenticationProvider, InitializingBean, MessageSourceAware {
  // ......
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication, this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports", "Only UsernamePasswordAuthenticationToken is supported"));
        String username = authentication.getPrincipal() == null ? "NONE_PROVIDED" : authentication.getName();
        boolean cacheWasUsed = true;
        UserDetails user = this.userCache.getUserFromCache(username);
        if (user == null) {
            cacheWasUsed = false;

            try {
                user = this.retrieveUser(username, (UsernamePasswordAuthenticationToken)authentication);
            } catch (UsernameNotFoundException var6) {
                this.logger.debug("User '" + username + "' not found");
                if (this.hideUserNotFoundExceptions) {
                    throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
                }

                throw var6;
            }

            Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");
        }

        try {
            this.preAuthenticationChecks.check(user);
            this.additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken)authentication);
        } catch (AuthenticationException var7) {
            if (!cacheWasUsed) {
                throw var7;
            }

            cacheWasUsed = false;
            user = this.retrieveUser(username, (UsernamePasswordAuthenticationToken)authentication);
            this.preAuthenticationChecks.check(user);
            this.additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken)authentication);
        }

        this.postAuthenticationChecks.check(user);
        if (!cacheWasUsed) {
            this.userCache.putUserInCache(user);
        }

        Object principalToReturn = user;
        if (this.forcePrincipalAsString) {
            principalToReturn = user.getUsername();
        }
```



获取当前登陆用户

cloud-service\user-center\src\main\java\com\cloud\user\controller\UserController.java
```
@Slf4j
@RestController
public class UserController {

    @Autowired
    private AppUserService appUserService;

    /** 当前登录用户 LoginAppUser */
    @GetMapping("/users/current")
    public LoginAppUser getLoginAppUser() {
        return AppUserUtil.getLoginAppUser();
    }

    @GetMapping(value = "/users-anon/internal", params = "username")
    public LoginAppUser findByUsername(String username) {
        return appUserService.findByUsername(username);
    }
    // .......
```

直接请求 localhost:7777/users/current
response:
```
{
    "timestamp": "2020-05-02T12:09:41.400+0000",
    "status": 401,
    "error": "Unauthorized",
    "message": "No message available",
    "path": "/users/current"
}
```

需要带上access_token
localhost:7777/users/current?access_token=aef49bd6-cb60-4809-ba24-c7292020d3dc
response:
```
{
    "id": 1,
    "username": "admin",
    "password": "$2a$10$3uOoX1ps14CxuotogUoDreW8zXJOZB9XeGdrC/xDV36hhaE8Rn9HO",
    "nickname": "测试1",
    "headImgUrl": "",
    "phone": "",
    "sex": 1,
    "enabled": true,
    "type": "APP",
    "createTime": "2018-01-17T08:57:01.000+0000",
    "updateTime": "2018-01-17T08:57:01.000+0000",
    "sysRoles": [
        {
            "id": 1,
            "code": "SUPER_ADMIN",
            "name": "超级管理员",
            "createTime": "2018-01-19T12:32:16.000+0000",
            "updateTime": "2018-01-19T12:32:18.000+0000"
        }
    ],
    "permissions": [
        "back:menu:set2role",
        "mail:update",
        "back:permission:delete",
        "role:permission:byroleid",
        "back:menu:save",
        "back:menu:query",
        "ip:black:query",
        "client:query",
        "ip:black:save",
        "file:del",
        "ip:black:delete",
        "mail:query",
        "back:user:query",
        "back:role:permission:set",
        "sms:query",
        "back:role:query",
        "client:save",
        "back:permission:query",
        "back:user:role:set",
        "back:role:save",
        "log:query",
        "file:query",
        "client:update",
        "back:menu:update",
        "back:role:update",
        "back:role:delete",
        "back:user:password",
        "back:menu:delete",
        "back:user:update",
        "menu:byroleid",
        "client:del",
        "mail:save",
        "user:role:byuid",
        "back:permission:save",
        "back:permission:update"
    ],
    "credentialsNonExpired": true,
    "accountNonLocked": true,
    "accountNonExpired": true
}
```

即用户中心获取access_token后，需要获取当前登陆用户信息/users/current，会通过security中配置的地址访问认证中心，得到结果后，通过工具类 AppUserUtil.getLoginAppUser(); 解析出当前登陆用户信息。

当我们要访问一个接口的时候，首先要会根据access_token到下面地址获取当前登陆用户,（包含权限信息，这样我们就可以利用框架本身来做鉴权，有关的用户获取，密码校验我们做了重写，参考SecurityConfig.java、UserDetailServiceImpl.java）
```
security:
  oauth2:
    resource:
      user-info-uri: http://local.gateway.com:8080/api-o/user-me
      prefer-token-info: false
```


cloud-service\oauth-center\src\main\java\com\cloud\oauth\config\ResourceServerConfig.java
```
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
// ......
	/**
	 * 判断来源请求是否包含oauth2授权信息<br>
	 * url参数中含有access_token,或者header里有Authorization
	 */
	private static class OAuth2RequestedMatcher implements RequestMatcher {
		@Override
		public boolean matches(HttpServletRequest request) {
			// 请求参数中包含access_token参数
			if (request.getParameter(OAuth2AccessToken.ACCESS_TOKEN) != null) {
				return true;
			}

			// 头部的Authorization值以Bearer开头
			String auth = request.getHeader("Authorization");
			if (auth != null) {
				return auth.startsWith(OAuth2AccessToken.BEARER_TYPE);
			}
			return false;
		}
	}

}
```


我们有两种方式来访问接口
1. url参数中含有access_token http://localhost:7777/users/current?access_token=0cf23b5f-912f-46c4-9fd0-5402398b0f7f
2. header里有Authorization

|  key  |  价格  |
|  :----  |  :----  |
|  Authorization  |  Bearer 0cf23b5f-912f-46c4-9fd0-5402398b0f7f  |








---
<h2 id="05.5">05.5 生成access_token的核心源码</h2>

---

[UML-TokenEndpoint](https://github.com/xie-chong/cloud-service/issues/4)

登陆成功之后产生access_token

入口 org\springframework\security\oauth2\provider\endpoint\TokenEndpoint.class
```
    @RequestMapping(
        value = {"/oauth/token"},
        method = {RequestMethod.POST}
    )
    public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal, @RequestParam Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
```
可以使用POST请求来测试

REQUEST：   
http://localhost:8888/oauth/token?grant_type=password&client_id=system&client_secret=system&scope=app&username=admin&password=admin

参数对应表 ```select * from oauth_client_details;```
该表也是底层核心所使用的org\springframework\security\oauth2\provider\client\JdbcClientDetailsService.class

RESPONSE:
```
{
    "access_token": "0cf23b5f-912f-46c4-9fd0-5402398b0f7f",
    "token_type": "bearer",
    "refresh_token": "d33f351a-2eae-419f-a674-732209d75834",
    "expires_in": 28799,
    "scope": "app"
}
```


**TokenEndpoint.class 重点逻辑 postAccessToken() 产生了access_token、refresh_token**
```
public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal, @RequestParam Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
            // ......

            ClientDetails authenticatedClient = this.getClientDetailsService().loadClientByClientId(clientId);
            TokenRequest tokenRequest = this.getOAuth2RequestFactory().createTokenRequest(parameters, authenticatedClient);

            // ......

                    OAuth2AccessToken token = this.getTokenGranter().grant(tokenRequest.getGrantType(), tokenRequest);
            // ......
                }
            }
        }
    }
```

项目 cloud-service 通过如下方法在redis里面查询不到 access_token、refresh_token，每次登陆都是重新生成access_token、refresh_token。

org\springframework\security\oauth2\provider\token\store\redis\RedisTokenStore.class
```
public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
        String key = this.authenticationKeyGenerator.extractKey(authentication);
        byte[] serializedKey = this.serializeKey("auth_to_access:" + key);
        byte[] bytes = null;
        RedisConnection conn = this.getConnection();

        byte[] bytes;
        try {
            bytes = conn.get(serializedKey);
        } finally {
            conn.close();
        }
```

**在基于springboot框架的项目中，若底层已经有实现逻辑，我们想改变，那么就必须使用配置类来加载和实则自己的实现**

比如此处，```public interface ClientDetailsService {}```的实现是```public class JdbcClientDetailsService {}```，而我们想通过redis来做个缓存优化，于是我们创建了```public class RedisClientDetailsService extends JdbcClientDetailsService {}```，再通过配置类来加载相关的实现逻辑```public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {}```

**refresh_token的作用**

* 当access_token未过期时，返回的access_token值不变，但时间在减小；
* 当access_token过期时，我们可以使用refresh_token来重新获取access_token，此时获取的access_token是一个新值，refresh_token的值不变；
* 若采用jwt，则每次刷新之后access_token、refresh_token都会发生变化。

直接请求登陆接口，此时不需要用户名和密码，其他参数响应的变化一下 grant_type=refresh_token，最后追加上 refresh_token=d33f351a-2eae-419f-a674-732209d75834

REQUEST:

http://localhost:8888/oauth/token?grant_type=refresh_token&client_id=system&client_secret=system&scope=app&refresh_token=d33f351a-2eae-419f-a674-732209d75834










---
<h2 id="05.6">05.6 根据 access_token 获取当前用户的核心源码</h2>

---

[UML-OAuth2AuthenticationProcessingFilter](https://github.com/xie-chong/cloud-service/issues/5)

### Filter

注解 **@EnableResourceServer** 帮我们加入了 org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter，该filter帮我们从request里解析出 access_token(先从头里找```request.getHeaders("Authorization");```，不存在再从参数里面找```request.getParameter("access_token");```)，转换成Authentication对象，并通过org.springframework.security.oauth2.provider.token.DefaultTokenServices根据access_token和认证服务器配置里的TokenStore从redis或者jwt里解析出用户存储到SecurityContext里。

 **注意**：认证中心的@EnableResourceServer和别的微服务里的@EnableResourceServer有些不同。别的微服务是通过org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices来获取用户的。

cloud-service\oauth-center\src\main\java\com\cloud\oauth\config\ResourceServerConfig.java
```
/** 资源服务配置 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
```

### 获取当前登陆用户

cloud-service\oauth-center\src\main\java\com\cloud\oauth\controller\OAuth2Controller.java
```
@Slf4j
@RestController
@RequestMapping
public class OAuth2Controller {
    /**
     * 当前登陆用户信息
     * security获取当前登录用户的方法是SecurityContextHolder.getContext().getAuthentication()
     * 返回值是接口org.springframework.security.core.Authentication，又继承了Principal
     * 这里的实现类是org.springframework.security.oauth2.provider.OAuth2Authentication
     */
    @GetMapping("/user-me")
    public Authentication principal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.debug("user-me:{}", authentication.getName());
        return authentication;
    }
// ......
```

即**先通过filter设置，然后再请求"/user-me"获取**









---
<h2 id="05.7">05.7 认证中心获取当前登陆用户核心代码</h2>

---

[UML-05-7](https://github.com/xie-chong/cloud-service/issues/6)

重点逻辑代码

org\springframework\security\oauth2\provider\authentication\OAuth2AuthenticationManager.class
```
	// ......
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication == null) {
            throw new InvalidTokenException("Invalid token (token not found)");
        } else {
            String token = (String)authentication.getPrincipal();
            OAuth2Authentication auth = this.tokenServices.loadAuthentication(token);
	// ......
```

org\springframework\security\oauth2\provider\token\DefaultTokenServices.class
```
// ......
public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException, InvalidTokenException {
        OAuth2AccessToken accessToken = this.tokenStore.readAccessToken(accessTokenValue);
        if (accessToken == null) {
            throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
        } else if (accessToken.isExpired()) {
            this.tokenStore.removeAccessToken(accessToken);
            throw new InvalidTokenException("Access token expired: " + accessTokenValue);
        } else {
            OAuth2Authentication result = this.tokenStore.readAuthentication(accessToken);
            if (result == null) {
                throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
            } else {
                if (this.clientDetailsService != null) {
                    String clientId = result.getOAuth2Request().getClientId();

                    try {
                        this.clientDetailsService.loadClientByClientId(clientId);
                    } catch (ClientRegistrationException var6) {
                        throw new InvalidTokenException("Client not valid: " + clientId, var6);
                    }
                }

                return result;
            }
        }
    }
// ......
```

**test**

1. 获取access_token
请求 http://localhost:8888/oauth/token?grant_type=password&client_id=system&client_secret=system&scope=app&username=admin&password=admin
2. debug模式下，查看从redis获取access_token流程
请求 http://localhost:8888/user-me?access_token=314b2379-5802-409a-a843-71d6f47ed038
其中涉及序列化后```this.serializeKey("access:" + tokenValue);
// ...... this.deserializeAccessToken(bytes)```。**redis key**为```"access:" + tokenValue```
3. 有了access_token之后，再获取 OAuth2Authentication 对象```OAuth2Authentication result = this.tokenStore.readAuthentication(accessToken);```。**redis key**为```"auth:" + tokenValue```








---
<h2 id="05.8">05.8 别的微服务获取当前登陆用户核心代码</h2>

---

[UML-05-8](https://github.com/xie-chong/cloud-service/issues/7)

比如用户中心也有注解**@EnableResourceServer**，其中的filter将会把access_token解析出来，关键的区别在于
* 认证中心使用的是 org\springframework\security\oauth2\provider\token\DefaultTokenServices.class
* 别的微服务使用的是 org\springframework\boot\autoconfigure\security\oauth2\resource\UserInfoTokenServices.class


org\springframework\security\oauth2\provider\authentication\OAuth2AuthenticationManager.class
```
public class OAuth2AuthenticationManager implements AuthenticationManager, InitializingBean {
    private ResourceServerTokenServices tokenServices;
    // ......

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            // ......
            OAuth2Authentication auth = this.tokenServices.loadAuthentication(token);
            // ......
```

**user-info-uri原理 **是在授权服务器认证后将认证信息Principal通过形参绑定的方法通过URL的方式获取用户信息。换句话说，就是当有了 access_token 之后，就会根据配置的 security 地址 + access_token ，发起请求到认证中心获取当前登录用户信息(```this.getMap(this.userInfoEndpointUrl, accessToken)```)。

cloud-service\config-center\src\main\resources\configs\dev\user-center.yml
```
security:
  oauth2:
    resource:
      user-info-uri: http://localhost:8888/user-me
      prefer-token-info: false
```

org\springframework\boot\autoconfigure\security\oauth2\resource\UserInfoTokenServices.class
```
public class UserInfoTokenServices implements ResourceServerTokenServices {
    // ......
    public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {
        Map<String, Object> map = this.getMap(this.userInfoEndpointUrl, accessToken);
        if (map.containsKey("error")) {
            if (this.logger.isDebugEnabled()) {
                this.logger.debug("userinfo returned error: " + map.get("error"));
            }

            throw new InvalidTokenException(accessToken);
        } else {
            return this.extractAuthentication(map);
        }
    }
    // ......
```


**那么底层代码是如何来决定使用哪一个实现类呢？（DefaultTokenServices.class、UserInfoTokenServices.class）**

org\springframework\security\oauth2\config\annotation\web\configurers\ResourceServerSecurityConfigurer.class
```
public final class ResourceServerSecurityConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    // ......
    private AuthenticationManager oauthAuthenticationManager(HttpSecurity http) {
        OAuth2AuthenticationManager oauthAuthenticationManager = new OAuth2AuthenticationManager();
        if (this.authenticationManager != null) {
            if (!(this.authenticationManager instanceof OAuth2AuthenticationManager)) {
                return this.authenticationManager;
            }

            oauthAuthenticationManager = (OAuth2AuthenticationManager)this.authenticationManager;
        }

        oauthAuthenticationManager.setResourceId(this.resourceId);
        oauthAuthenticationManager.setTokenServices(this.resourceTokenServices(http));
        oauthAuthenticationManager.setClientDetailsService(this.clientDetails());
        return oauthAuthenticationManager;
    }

    private ResourceServerTokenServices resourceTokenServices(HttpSecurity http) {
        this.tokenServices(http);
        return this.resourceTokenServices;
    }

    private ResourceServerTokenServices tokenServices(HttpSecurity http) {
        if (this.resourceTokenServices != null) {
            return this.resourceTokenServices;
        } else {
            DefaultTokenServices tokenServices = new DefaultTokenServices();
            tokenServices.setTokenStore(this.tokenStore());
            tokenServices.setSupportRefreshToken(true);
            tokenServices.setClientDetailsService(this.clientDetails());
            this.resourceTokenServices = tokenServices;
            return tokenServices;
        }
    }
    // ......
}
```

org\springframework\boot\autoconfigure\security\oauth2\resource\ResourceServerProperties.class
```
@ConfigurationProperties(
    prefix = "security.oauth2.resource"
)
public class ResourceServerProperties implements BeanFactoryAware {
    // ......
    private String userInfoUri;
    // ......
```

org\springframework\boot\autoconfigure\security\oauth2\resource\ResourceServerTokenServicesConfiguration.class
```
@Configuration
@ConditionalOnMissingBean({AuthorizationServerEndpointsConfiguration.class})
public class ResourceServerTokenServicesConfiguration {
    public ResourceServerTokenServicesConfiguration() {
    }

    // ......

    private static class TokenInfoCondition extends SpringBootCondition {
        private TokenInfoCondition() {
        }

        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
            Builder message = ConditionMessage.forCondition("OAuth TokenInfo Condition", new Object[0]);
            Environment environment = context.getEnvironment();
            Boolean preferTokenInfo = (Boolean)environment.getProperty("security.oauth2.resource.prefer-token-info", Boolean.class);
            if (preferTokenInfo == null) {
                preferTokenInfo = environment.resolvePlaceholders("${OAUTH2_RESOURCE_PREFERTOKENINFO:true}").equals("true");
            }

            String tokenInfoUri = environment.getProperty("security.oauth2.resource.token-info-uri");
            String userInfoUri = environment.getProperty("security.oauth2.resource.user-info-uri");
            if (!StringUtils.hasLength(userInfoUri) && !StringUtils.hasLength(tokenInfoUri)) {
                return ConditionOutcome.match(message.didNotFind("user-info-uri property").atAll());
            } else {
                return StringUtils.hasLength(tokenInfoUri) && preferTokenInfo ? ConditionOutcome.match(message.foundExactly("preferred token-info-uri property")) : ConditionOutcome.noMatch(message.didNotFind("token info").atAll());
            }
        }
    }
    
   // ......

```
另外需要注意的一点是，security的客户端和服务端pom.xml依赖是一样的。

```
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-oauth2</artifactId>
		</dependency>
```









---
<h2 id="05.9">05.9 redis 缓存 oauth2 中的 client 信息</h2>

---

[UML-05-9](https://github.com/xie-chong/cloud-service/issues/8)

org\springframework\security\oauth2\provider\client\JdbcClientDetailsService.class

JdbcClientDetailsService.class 去表oauth_client_details 中获取一些oauth认证需要的东西。
```
public class JdbcClientDetailsService implements ClientDetailsService, ClientRegistrationService {
    // ......

    public ClientDetails loadClientByClientId(String clientId) throws InvalidClientException {
        try {
            ClientDetails details = (ClientDetails)this.jdbcTemplate.queryForObject(this.selectClientDetailsSql, new JdbcClientDetailsService.ClientDetailsRowMapper(), new Object[]{clientId});
            return details;
        } catch (EmptyResultDataAccessException var4) {
            throw new NoSuchClientException("No client with requested id: " + clientId);
        }
    }
    // ......
}
```

cloud-service\oauth-center\src\main\java\com\cloud\oauth\service\impl\RedisClientDetailsService.java
```
/**
 * 将oauth_client_details表数据缓存到redis，毕竟该表改动非常小，而且数据很少，这里做个缓存优化<br>
 * 如果有通过界面修改client的需求的话，不要用JdbcClientDetailsService了，请用该类，否则redis里有缓存<br>
 * 如果手动修改了该表的数据，请注意清除redis缓存，是hash结构，key是client_details
 *
 */
@Slf4j
@Service
public class RedisClientDetailsService extends JdbcClientDetailsService {
    // ......

    private StringRedisTemplate stringRedisTemplate;

    public RedisClientDetailsService(DataSource dataSource) {
        super(dataSource);
    }

    // 缓存client的redis key，这里是hash结构存储
    private static final String CACHE_CLIENT_KEY = "client_details";

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws InvalidClientException {
        ClientDetails clientDetails = null;
        // 先从redis获取
        String value = (String) stringRedisTemplate.boundHashOps(CACHE_CLIENT_KEY).get(clientId);
        if (StringUtils.isBlank(value)) {
            clientDetails = cacheAndGetClient(clientId);
        } else {
            clientDetails = JSONObject.parseObject(value, BaseClientDetails.class);
        }
        return clientDetails;
    }
    // ......

     // 将oauth_client_details全表刷入redis
    public void loadAllClientToCache() {
        if (stringRedisTemplate.hasKey(CACHE_CLIENT_KEY) == Boolean.TRUE) {
            return;
        }
        log.info("将oauth_client_details全表刷入redis");

        List<ClientDetails> list = super.listClientDetails();
        if (CollectionUtils.isEmpty(list)) {
            log.error("oauth_client_details表数据为空，请检查");
            return;
        }
    // ......
}
```

cloud-service\oauth-center\src\main\java\com\cloud\oauth\config\AuthorizationServerConfig.java   
```
    // ......
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(redisClientDetailsService);
        redisClientDetailsService.loadAllClientToCache();// 在项目启动的时候，会把表里的数据缓存到redis里面
    }
    // ......
```









---
<h2 id="06.1">06.1 网关 zuul</h2>

---

cloud-service\gateway-zuul\pom.xml
```
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-netflix-zuul</artifactId>
		</dependency>
```

cloud-service\gateway-zuul\src\main\java\com\cloud\gateway\GatewayApplication.java
```
@EnableFeignClients
@EnableZuulProxy
@EnableDiscoveryClient
@SpringBootApplication
public class GatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}
}
```

### 转发规则的核心配置
cloud-service\config-center\src\main\resources\configs\dev\gateway-zuul.yml
```
zuul:
  ignored-services: '*' # 表示禁用默认路由，只认我们自己配置的路由.
  sensitiveHeaders: 
  routes:
    oauth:
      path: /api-o/**
	  # stripPrefix: true
      serviceId: oauth-center
    api-u:
      path: /api-u/**
      serviceId: user-center
    backend:
      path: /api-b/**
      serviceId: manage-backend
    log:
      path: /api-l/**
      serviceId: log-center
    file:
      path: /api-f/**
      serviceId: file-center
    sms:
      path: /api-n/**
      serviceId: notification-center
  host:
    connect-timeout-millis: 10000
    socket-timeout-millis: 60000
  add-proxy-headers: true
  ribbon:
    eager-load:
      enabled: true
```

zuul 一般是用来作为网关服务开发，在涉及到转发路由的时候，zuul会改写request中的头部信息。那么怎么样在项目中配置呢？请看下面：   

* sensitiveHeaders会过滤客户端附带的headers
例如：zuul.sensitiveHeaders=Cookie,Set-Cookie
如果客户端在发请求是带了Cookie，那么Cookie不会传递给下游服务。
默认：zuul.sensitiveHeaders= 
什么都不设置代表不过滤任何信息，但 zuul.sensitiveHeaders=  一定要附上  。

* zuul.ignoredHeaders会过滤服务之间通信附带的headers
例如：zuul.ignoredHeaders=Cookie,Set-Cookie
如果客户端在发请求是带了Cookie，那么Cookie依然会传递给下游服务。但是如果下游服务再转发就会被过滤。作用与上面敏感的Header差不多，事实上sensitive-headers会被添加到ignored-headers中。

* 还有一种情况就是客户端带了Cookie，在ZUUL的Filter中又addZuulRequestHeader("Cookie", "new"),
那么客户端的Cookie将会被覆盖，此时不需要sensitiveHeaders。
如果设置了sensitiveHeaders: Cookie，那么Filter中设置的Cookie依然不会被过滤。

**zuul 里面的 stripPrefix 怎么使用？**
stripPrefix ：代理前缀默认会从请求路径中移除，通过该设置关闭移除功能，
* 当 stripPrefix=true 的时 （会移除）
（http://local.gateway.com:8080/api-o/user-me -> http://local.gateway.com:8080/user-me，
* 当stripPrefix=false的时（不会移除）
（http://local.gateway.com:8080/api-o/user-me -> http://local.gateway.com:8080/api-o/user-me

### 跨域配置

cloud-service\gateway-zuul\src\main\java\com\cloud\gateway\config\CrossDomainConfig.java
```
/**
 * 跨域配置<br>
 * 页面访问域名和后端接口地址的域名不一致时，会先发起一个OPTIONS的试探请求<br>
 * 如果不设置跨域的话，js将无法正确访问接口，域名一致的话，不存在这个问题
 */
@Configuration
public class CrossDomainConfig {

    /**  跨域支持 */
    @Bean
    public CorsFilter corsFilter() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // 允许cookies跨域
        config.addAllowedOrigin("*");// #允许向该服务器提交请求的URI，*表示全部允许
        config.addAllowedHeader("*");// #允许访问的头信息,*表示全部
        config.setMaxAge(18000L);// 预检请求的缓存时间（秒），即在这个时间段里，对于相同的跨域请求不会再预检了
        config.addAllowedMethod("*");// 允许提交请求的方法，*表示全部允许
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    //两种方式任选其一即可
//    @Bean
//    public WebMvcConfigurer corsConfigurer() {
//        return new WebMvcConfigurer() {
//            @Override
//            public void addCorsMappings(CorsRegistry registry) {
//                registry.addMapping("/**") // 拦截所有权请求
//                        .allowedMethods("*") // 允许提交请求的方法，*表示全部允许
//                        .allowedOrigins("*") // #允许向该服务器提交请求的URI，*表示全部允许
//                        .allowCredentials(true) // 允许cookies跨域
//                        .allowedHeaders("*") // #允许访问的头信息,*表示全部
//                        .maxAge(18000L); // 预检请求的缓存时间（秒），即在这个时间段里，对于相同的跨域请求不会再预检了
//            }
//        };
//    }
}
```

### spring security配置

cloud-service\gateway-zuul\src\main\java\com\cloud\gateway\config\SecurityConfig.java
```
@EnableOAuth2Sso
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.headers().frameOptions().sameOrigin();
		http.cors();
	}
}
```

关于**@EnableOAuth2Sso**可以自行查看相关文档https://www.cnblogs.com/trust-freedom/p/12002089.html

### feign

cloud-service\gateway-zuul\src\main\java\com\cloud\gateway\feign\Oauth2Client.java
```
@FeignClient("oauth-center")
public interface Oauth2Client {

    /**
     * 获取access_token<br>
     * 这是spring-security-oauth2底层的接口，类TokenEndpoint<br>
     * 感兴趣可看下视频章节05.5 生成access_token的核心源码
     *
     * @param parameters
     * @return
     * @see org.springframework.security.oauth2.provider.endpoint.TokenEndpoint
     */
    @PostMapping(path = "/oauth/token")
    Map<String, Object> postAccessToken(@RequestParam Map<String, String> parameters);

    /**
     * 删除access_token和refresh_token<br>
     * 认证中心的OAuth2Controller方法removeToken
     *
     * @param access_token
     */
    @DeleteMapping(path = "/remove_token")
    void removeToken(@RequestParam("access_token") String access_token);
}
```

### filter

cloud-service\gateway-zuul\src\main\java\com\cloud\gateway\filter\BlackIPAccessFilter.java
```
/**
 * 黑名单IP拦截<br>
 * 黑名单ip变化不会太频繁，<br>
 * 考虑到性能，我们不实时掉接口从别的服务获取了，<br>
 * 而是定时把黑名单ip列表同步到网关层,
 */
@Component
public class BlackIPAccessFilter extends ZuulFilter {

	/**  黑名单列表 */
	private Set<String> blackIPs = new HashSet<>();

	@Override
	public boolean shouldFilter() {
		if (blackIPs.isEmpty()) {
			return false;
		}

		RequestContext requestContext = RequestContext.getCurrentContext();
		HttpServletRequest request = requestContext.getRequest();
		String ip = getIpAddress(request);

		return blackIPs.contains(ip);// 判断ip是否在黑名单列表里
	}

	@Override
	public Object run() {//真正的过滤逻辑
		RequestContext requestContext = RequestContext.getCurrentContext();
		requestContext.setResponseStatusCode(HttpStatus.FORBIDDEN.value());
		requestContext.setResponseBody("black ip");
		requestContext.setSendZuulResponse(false);

		return null;
	}

	@Override
	public int filterOrder() {
		return 0;
	}

	@Override
	public String filterType() {
		return FilterConstants.PRE_TYPE;
	}
	// ......
```


通过继承ZuulFilter然后覆写上面的4个方法，就可以实现一个简单的过滤器，下面就相关注意点进行说明
filterType：返回一个字符串代表过滤器的类型，在zuul中定义了四种不同生命周期的过滤器类型，具体如下：   
* pre：可以在请求被路由之前调用
* route：在路由请求时候被调用
* post：在route和error过滤器之后被调用
* error：处理请求时发生错误时被调用

     Zuul的主要请求生命周期包括“pre”，“route”和“post”等阶段。对于每个请求，都会运行具有这些类型的所有过滤器。

filterOrder：通过int值来定义过滤器的执行顺序

shouldFilter：返回一个boolean类型来判断该过滤器是否要执行，所以通过此函数可实现过滤器的开关。在上例中，我们直接返回true，所以该过滤器总是生效

run：过滤器的具体逻辑。需要注意，这里我们通过ctx.setSendZuulResponse(false)令zuul过滤该请求，不对其进行路由转发，然后通过ctx.setResponseStatusCode(401)设置了其返回的错误码

[spring cloud-zuul的Filter详解_CSDN](https://blog.csdn.net/liuchuanhong1/article/details/62236793)

cloud-service\gateway-zuul\src\main\java\com\cloud\gateway\filter\InternalURIAccessFilter.java
```
/**
 * 过滤uri<br>
 * 该类uri不需要登陆，但又不允许外网通过网关调用，只允许微服务间在内网调用，<br>
 * 为了方便拦截此场景的uri，我们自己约定一个规范，及uri中含有-anon/internal<br>
 * 如在oauth登陆的时候用到根据username查询用户，<br>
 * 用户系统提供的查询接口/users-anon/internal肯定不能做登录拦截，而该接口也不能对外网暴露<br>
 * 如果有此类场景的uri，请用这种命名格式，
 *
 */
@Component
public class InternalURIAccessFilter extends ZuulFilter {
```

### 定时同步黑名单IP @Scheduled

cloud-service\gateway-zuul\src\main\java\com\cloud\gateway\filter\BlackIPAccessFilter.java
```
	/**  定时同步黑名单IP */
	@Scheduled(cron = "${cron.black-ip}")
	public void syncBlackIPList() {
		try {
			Set<String> list = backendClient.findAllBlackIPs(Collections.emptyMap());
			blackIPs = list;
		} catch (Exception e) {
			// do nothing
		}
	}
```

cloud-service\config-center\src\main\resources\configs\dev\gateway-zuul.yml
```
cron:
  black-ip: 0 0/5 * * * ?
```






---
<h2 id="06.2">06.2 网关端口说明</h2>

---

如果有多个网关，需要使用ngix做代理，此时需要明确每一个网关服务的ip、port


```
***********************《 ngix 》**************************
******************<<<<<<******>>>>>>>**********************
****************<<<<*****************>>>>******************
**************<<************************>>*****************
*******《 网关1 》***********************《 网关2 》********
```






---
<h2 id="07.1">07.1 日志中心讲解</h2>

---

### 日志存储调用

由于日志采用了RabbitMQ的方式来创建，可以在日志服务宕机重启后，继续消费队列中存在的消息做相应的处理。   
cloud-service\log-center\pom.xml
```
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-amqp</artifactId>
		</dependency>
```

cloud-service\log-center\src\main\java\com\cloud\log\consumer\LogConsumer.java
```
/** 从mq队列消费日志数据 */
@Component
@RabbitListener(queues = LogQueue.LOG_QUEUE) // 监听队列
public class LogConsumer {
	private static final Logger logger = LoggerFactory.getLogger(LogConsumer.class);
	@Autowired
	private LogService logService;

	/**  处理消息 */
	@RabbitHandler
	public void logHandler(Log log) {
		try {
			logService.save(log);
		} catch (Exception e) {
			logger.error("保存日志失败，日志：{}，异常：{}", log, e);
		}
	}
}
```

**注意**：消费mq时，尽量加上异常处理，否则出现异常时可能导致消息没法消费，日志不断扩大。

同时 log-center 也提供了接口（feign），可以调用接口来存储日志   
cloud-service\log-center\src\main\java\com\cloud\log\controller\LogController.java
```
@RestController
public class LogController {

	@Autowired
	private LogService logService;

	@PostMapping("/logs-anon/internal")
	public void save(@RequestBody Log log) {
		logService.save(log);
	}
	// ......
```

日志的存储是要实现下面接口
```
public interface LogService {
	/** 保存日志 */
	void save(Log log);
	Page<Log> findLogs(Map<String, Object> params);
}
```

* 存储到 Mysql ，LogServiceImpl.java
* 存储到 elasticsearch ，EsLogServiceImpl.java

日志表 t_log 对应代码里面的对象   
cloud-service\api-model\src\main\java\com\cloud\model\log\Log.java
```
/** 日志对象 */
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Log implements Serializable {
	private static final long serialVersionUID = -5398795297842978376L;
	private Long id;
	private String username;// 用户名
	private String module;// 模块
	private String params;// 参数值
	private String remark;// 备注
	private Boolean flag;// 是否执行成功
	private Date createTime;
}
```

### 配置文件

cloud-service\log-center\src\main\java\com\cloud\log\config\AsycTaskExecutorConfig.java
```
/** 线程池配置、启用异步 */
@EnableAsync(proxyTargetClass = true)
@Configuration
public class AsycTaskExecutorConfig {
	@Bean
	public TaskExecutor taskExecutor() {
		ThreadPoolTaskExecutor taskExecutor = new ThreadPoolTaskExecutor();
		taskExecutor.setCorePoolSize(50);
		taskExecutor.setMaxPoolSize(100);

		return taskExecutor;
	}
}
```

cloud-service\log-center\src\main\java\com\cloud\log\config\RabbitmqConfig.java
```
/**  rabbitmq配置 */
@Configuration
public class RabbitmqConfig {

	/**  声明队列 */
	@Bean
	public Queue logQueue() {
		Queue queue = new Queue(LogQueue.LOG_QUEUE);
		return queue;
	}
}
```

cloud-service\log-center\src\main\java\com\cloud\log\config\ElasticSearchConfig.java
```
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "elasticsearch")
public class ElasticSearchConfig {
```

cloud-service\log-center\src\main\java\com\cloud\log\config\ResourceServerConfig.java
```
/** 资源服务配置 */
@EnableResourceServer
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().exceptionHandling()
				.authenticationEntryPoint(
						(request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
				.and().authorizeRequests().antMatchers(PermitAllUrl.permitAllUrl("/logs-anon/**")).permitAll() // 放开权限的url
				.anyRequest().authenticated().and().httpBasic();
	}
}
```
不允许其他连接通过网关访问，只允许内部服务之间相互调用











---
<h2 id="07.2">07.2 日志组件 aop 实现</h2>

---

**怎么通过消息把日志发送到日志中心去？**

基于自定义注解 **@LogAnnotation**，通过aop的方式拦截请求，获取module以及params。


cloud-service\api-model\src\main\java\com\cloud\model\log\LogAnnotation.java
```
@Target({ ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
public @interface LogAnnotation {

	/** 日志模块 */
	String module();

	/**
	 * 记录参数<br>
	 * 尽量记录普通参数类型的方法，和能序列化的对象
	*/
	boolean recordParam() default true;
}

```

[Java自定义注解_CN](https://www.cnblogs.com/liangweiping/p/3837332.html)   



cloud-service\user-center\src\main\java\com\cloud\user\controller\UserController.java
```
@Slf4j
@RestController
public class UserController {
	// ......
   /** 修改自己的个人信息 */
    @LogAnnotation(module = "修改个人信息")
    @PutMapping("/users/me")
    public AppUser updateMe(@RequestBody AppUser appUser) {
        AppUser user = AppUserUtil.getLoginAppUser();
        appUser.setId(user.getId());

        appUserService.updateAppUser(appUser);

        return appUser;
    }
	// ......
}
```

cloud-service\file-center\src\main\java\com\cloud\file\controller\FileController.java
```
@RestController
@RequestMapping("/files")
public class FileController {
	@Autowired
	private FileServiceFactory fileServiceFactory;
	/**
	 * 文件上传<br>
	 * 根据fileSource选择上传方式，目前仅实现了上传到本地<br>
	 * 如有需要可上传到第三方，如阿里云、七牛等
	 */
	@LogAnnotation(module = "文件上传", recordParam = false)
	@PostMapping
	public FileInfo upload(@RequestParam("file") MultipartFile file, String fileSource) throws Exception {
		FileService fileService = fileServiceFactory.getFileService(fileSource);
		return fileService.upload(file);
	}
	// ......
```

**aop 方式写成一个log-starter，抽离抽来作为一个组件**

当需要做日志记录时，只需要引入依赖。在需要记录日志的方法上写上注解 **@LogAnnotation**。参考用户中心。   

cloud-service\user-center\pom.xml
```
		<dependency>
			<groupId>com.cloud</groupId>
			<artifactId>log-starter</artifactId>
			<version>${project.version}</version>
		</dependency>
```

log-starter 是参照springBoot的自动注入来写的。

cloud-service\log-starter\pom.xml
```
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<artifactId>log-starter</artifactId>
	<packaging>jar</packaging>

	<parent>
		<groupId>com.cloud</groupId>
		<artifactId>cloud-service</artifactId>
		<version>2.0</version>
	</parent>

	<dependencies>
		<dependency>
			<groupId>com.cloud</groupId>
			<artifactId>commons</artifactId>
			<version>${project.version}</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-aop</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-amqp</artifactId>
		</dependency>
	</dependencies>

</project>
```


springBoot的自动配置大部分归功于 org.springframework.boot.autoconfigure.EnableAutoConfiguration=\

比如用户中心启动时的包为 ```package com.cloud.user;```，并扫不到 log-starter 下面的包```com.cloud.log.autoconfigure```。于是我们参照springBoot自动注入的原理，创建一个文件，在启动时把里面配置的内容加载成一个bean。

cloud-service\log-starter\src\main\resources\META-INF\spring.factories
```
org.springframework.boot.autoconfigure.EnableAutoConfiguration=\
com.cloud.log.autoconfigure.LogAutoConfiguration,\
com.cloud.log.autoconfigure.LogAop
```

以防万一的队列声明   
cloud-service\log-starter\src\main\java\com\cloud\log\autoconfigure\LogAutoConfiguration.java
```
@Configuration
public class LogAutoConfiguration {

    /**
     * 声明队列<br>
     * 如果日志系统已启动，或者mq上已存在队列 LogQueue.LOG_QUEUE，此处不用声明此队列<br>
     * 此处声明只是为了防止日志系统启动前，并且没有队列 LogQueue.LOG_QUEUE的情况下丢失消息
     *
     * @return
     */
	     @Bean
    public Queue logQueue() {
        return new Queue(LogQueue.LOG_QUEUE);
    }
	// ......
```

cloud-service\log-starter\src\main\java\com\cloud\log\autoconfigure\LogAop.java
```
/** aop实现日志 */
@Aspect
public class LogAop {

    private static final Logger logger = LoggerFactory.getLogger(LogAop.class);

    @Autowired
    private AmqpTemplate amqpTemplate;

    /** 环绕带注解 @LogAnnotation的方法做aop */
    @Around(value = "@annotation(com.cloud.model.log.LogAnnotation)")
    public Object logSave(ProceedingJoinPoint joinPoint) throws Throwable {
```














