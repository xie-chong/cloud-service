# 随笔

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


## 04.7 多账户-用户凭证表

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

## 04.8 放开某url的权限

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



## 05.1 认证中心代码结构

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


## 05.2 FeignClient简单介绍

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

## 05.3 认证中心配置类和接口

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
