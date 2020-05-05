# <p align="center">随笔</p>

- [04.7 多账户-用户凭证表](#04.7)   
- [04.8 放开某url的权限](#04.8)   
- [05.1 认证中心代码结构](#05.1)   
- [05.2 FeignClient简单介绍](#05.2)   
- [05.3 认证中心配置类和接口](#05.3)   
- [05.4 登陆和鉴权](#05.4)   
- [05.5 生成 access_token 的核心源码](#05.5)   
- [05.6 根据 access_token 获取当前用户的核心源码](#05.6)   




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

注解**@EnableResourceServer**帮我们加入了 org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter，该filter帮我们从request里解析出 access_token(先从头里找```request.getHeaders("Authorization");```，不存在再从参数里面找```request.getParameter("access_token");```)，转换成Authentication对象，并通过org.springframework.security.oauth2.provider.token.DefaultTokenServices根据access_token和认证服务器配置里的TokenStore从redis或者jwt里解析出用户存储到SecurityContext里。

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

即先通过filter设置，然后再请求"/user-me"获取
