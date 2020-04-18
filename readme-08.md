# <p align="center">eureka添加密码访问模式</p>

- [1 | 注册中心register-center修改](#01)    
  - [1.1 认证中心的pom添加security依赖](#1.1)   
  - [1.2 修改register-center的bootstrap.yml](#1.2)   
  - [1.3 注册中心加入一个配置类](#1.3)   
- [2 | 各服务的bootstrap.yml修改](#02)   




---
---
---
<h1 id="01">1 | 注册中心register-center修改</h1>

---


<h2 id="1.1">1.1 认证中心的pom添加security依赖</h2>

在register-center的pom.xml里加入以下依赖

```
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-starter-security</artifactId>
		</dependency>
```

或者

```
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
```


<h2 id="1.2">1.2 修改register-center的bootstrap.yml</h2>

如下所示，加入 **security** 节点，其中name和password是自定义的

```
spring:
  application:
    name: register-center
    security:
      user:
        name: xiaowei
        password: xiaoweijiagou
```


<h2 id="1.3">1.3 注册中心加入一个配置类</h2>

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests().anyRequest().authenticated().and().httpBasic();
    }
}
```

将该类写在注册中心的一个位置即可，如下
- register-center
  - src
      - main
         - java
             - com.cloud.register
               - RegisterCenterApplication.java
               - WebSecurityConfig.java
         - resources
           - .gitignore
           - bootstrap.yml
  - .gitignore
  - pom.xml
  - README.md

因为**配置文件在新版本中发生了变化，需要通过配置类来设置获取**。

Spring Boot 1.5.x版本中：
```
security:
  basic:
    enabled: true
```

Spring Boot 2.x中变为：
```
spring:
  security:
    basic:
      enabled: true
```





---
<h1 id="02">2 | 各服务的bootstrap.yml修改</h1>

---

在我们所有的服务里（包括注册中心），都有以下节点
 ```
 eureka:
  client:
    serviceUrl:
      defaultZone: http://local.register.com:${server.port}/eureka/
 ```
 
有了该节点，微服务才去将自己注册到eureka上，如果我们的eureka添加了security的密码验证，那么该配置也需要改动一下(所有需要注册的服务，包括注册中心)，否则将连接不到eureka。

格式如下：   
```
http://用户名:密码@ip:端口/eureka/
```

如: http://xiaowei:xiaoweijiagou@local.register.com:8761/eureka/







