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





