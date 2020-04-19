# <p align="center">模块详细介绍和配置</p>

- [1丨项目结构](#1)   
- [2丨模块和配置](#2)   
  - [2.1 父pom.xml](#2.1)   
  - [2.2 注册中心](#2.2)   
    - [1) bootstrap.yml](#2.2.1)   
    - [2) 启动注册中心](#2.2.2)   
    - [3) 访问http://localhost:8761](#2.2.3)   
    - [4) 多注册中心](#2.2.4)   
  - [2.3 配置中心](#2.3)   
    - [1) bootstrap.yml](#2.3.1)   
    - [2) {profile}](#2.3.2)   
    - [3) 端口](#2.3.3)   
    - [4) 注册到注册中心](#2.3.4)   
    - [5) 注册中心里的显示](#2.3.5)   
    - [6) 配置中心底层核心源码](#2.3.6)   
  - [2.4 用户中心](#2.4)   
    - [1) 数据库脚本](#2.4.1)   
    - [2) bootstrap.yml](#2.4.2)   
    - [3) user-center.yml](#2.4.3)   
    - [4) 配置类](#2.4.4)   
  - [2.5 认证中心](#2.5)   
    - [1) 数据库脚本](#2.5.1)   
    - [2) bootstrap.yml](#2.5.2)   
    - [3) oauth-center.yml](#2.5.3)   
    - [4) 配置类](#2.5.4)   
  - [2.6 文件中心](#2.6)   
    - [1) 数据库脚本](#2.6.1)   
    - [2) bootstrap.yml](#2.6.2)   
    - [3) file-center.yml](#2.6.3)   
    - [4) 配置类](#2.6.4)   
  - [2.7 网关](#2.7)    
    - [1) gateway-zuul.yml](#2.7.1)   
    - [1) 配置类](#2.7.2)   
  - [2.8 日志组件 log-starter](#2.8)    
    - [1) spring.factories](#2.8.1)   
    - [2) 使用该组件](#2.8.2)   
  - [2.9 日志中心](#2.9)   
    - [1) log-center.yml](#2.9.1)   
    - [2) 配置类](#2.9.2)   
    - [3) 处理日志消息](#2.9.3)   
    - [4) 日志存储 mysql 和 elasticsearch 切换](#2.9.4) 
  - [2.10 后台管理系统](#2.10)   
    - [1) manage-backend.yml](#2.10.1)   
    - [2) 消息处理](#2.10.2)   
    - [3) 静态资源](#2.10.3)   




























---
---
---
<h1 id="1">1丨项目结构</h1>

---

+ cloud-service
   + .idea
   + api-model
   + commons
   + config-center
   + file-center
   + gateway-zuul
   + log-center
   + log-starter
   + manage-backend
   + monitor-center
   + notification-center
   + oauth-center
   + register-center
   + user-center
   + 文档
   + .gitignore
   + cloud-service.iml
   + pom.xml
   + README.md



---
<h1 id="2">2丨模块和配置</h1>

---

| 工程名 | 说明 |
| :----- | :----- |
| api-model | 数据创数对象、常量等 |
| cmmons | 工具类、公共常量等 |
| config-center | 配置中心 |
| file-center | 文件中心 |
| gateway-zuul | 网关 |
| log-center | 日志中心 |
| log-starter | 日志组件、别的项目直接引入该依赖即可 |
| manage-backend | 后台管理 |
| monitor-center | 监控中心 |
| oauth-center | 认证中心 |
| register-center | 注册中心 |
| user-center | 用户中心、用户、角色、权限 |


<h2 id="2.1">2.1 父pom.xml</h2>

**配置的各个模块目录**
```
	<modules>
		<module>register-center</module>
		<module>config-center</module>
		<module>gateway-zuul</module>
		<module>oauth-center</module>
		<module>monitor-center</module>
		<module>user-center</module>
		<module>api-model</module>
		<module>commons</module>
		<module>manage-backend</module>
		<module>log-center</module>
		<module>log-starter</module>
		<module>file-center</module>
		<module>notification-center</module>
	</modules>
```

**定义了一些jar包的版本号**
```
	<properties>
		<spring-cloud.version>Finchley.RELEASE</spring-cloud.version>
		<mybatis.version>1.3.2</mybatis.version>
		<jwt.version>0.9.1</jwt.version>
		<fastjson.version>1.2.47</fastjson.version>
		<commons-collections>4.1</commons-collections>
		<monitor.version>2.0.2</monitor.version>
		<swagger.version>2.8.0</swagger.version>
		<aliyun-sdk-oss.version>2.8.2</aliyun-sdk-oss.version>
		<aliyun-sdk-core.version>3.2.8</aliyun-sdk-core.version>
		<aliyun-sdk-dysmsapi.version>1.1.0</aliyun-sdk-dysmsapi.version>
		<elasticsearch.version>6.2.3</elasticsearch.version>
		<security-oauth2.version>2.3.3.RELEASE</security-oauth2.version>
		<docker.image.prefix>springboot</docker.image.prefix>
	</properties>
```


<h2 id="2.2">2.2 注册中心</h2>

- register-center
  - src
      - main
         - java
             - com.cloud.register
               - RegisterCenterApplication.java
         - resources
           - .gitignore
           - bootstrap.yml
  - .gitignore
  - pom.xml
  - README.md


<h3 id="2.2.1">1) bootstrap.yml</h3>

给应用取名字，设置启动端口号
```
spring:
  application:
    name: register-center
server:
  port: 8761
```

<h3 id="2.2.2">2) 启动注册中心</h3>

直接运行 **RegisterCenterApplication.java** 的main方法

<h3 id="2.2.3">3) 访问http://localhost:8761</h3>

给应用取名字，设置启动端口号
```
spring:
  application:
    name: register-center
server:
  port: 8761
```

<h3 id="2.2.2">2) 启动注册中心</h3>

直接运行 **RegisterCenterApplication.java** 的main方法

<h3 id="2.2.3">3) 访问http://localhost:8761</h3>

8761是bootstrap.yml里配置的系统端口号

**Spring Eureka 界面部分信息**

**Instances currently registered with Eureka**

| Application | AMIs | Availiability Zones | Status |
| :-----: | :-----: | :-----: | :-----: |
| REGISTER-CENTER | n/a(1) | (1) | UP(1)-[register-center:8761](http://ip:8761/info) |

Application列下的，REGISTER-CENTER就是我们在bootstrap.yml里指定的应用名，注册中心给我们大写处理了。

Status下显示的是我们在bootstrap.yml里的instance-id，如下所示，我们这里是应用名加端口号。 该配置为true的话，是用ip注册，否则是主机名注册，强烈建议配置为true。 点击会跳转到类似如下的地址http://ip:8761/info。 用这种方式，我们可以看到服务的具体ip地址和端口。
```
  instance:
    lease-expiration-duration-in-seconds: 15
    lease-renewal-interval-in-seconds: 5
    prefer-ip-address: true
    instance-id: ${spring.application.name}:${server.port}
```

<h3 id="2.2.4">4) 多注册中心</h3>

假设我们有两个注册中心8761、8762，那么他们之间需要相互注册
```
server:
  port: 8761
eureka:
  client:
    serviceUrl:
      defaultZone: http://local.register.com:8761/eureka/,http://local.register.com:8762/eureka/
```

```
server:
  port: 8762
eureka:
  client:
    serviceUrl:
      defaultZone: http://local.register.com:8761/eureka/,http://local.register.com:8762/eureka/
```

作为eureka的client，它可以只配置一个注册中心，也可以配置多注册中心。因为多注册中心之间会相互同步注册信息。
```
eureka:
  client:
    serviceUrl:
      defaultZone: http://local.register.com:8761/eureka/
```


<h2 id="2.3">2.3 配置中心</h2>

- config-center
  - src
    - main
      - java
        - com.cloud.config
          - ConfigCenterApplication.java
      - resources
        - configs.dev
          - file-center.yml
          - gateway-zuul.yml
          - log-center.yml
          - manage-backend.yml
          - notification-center.yml
          - oauth-center.yml
          - user-center.yml
          - bootstrap.yml
  - .gitignore
  - config-center.iml
  - pom.xml
  - README.md

<h3 id="2.3.1">1) bootstrap.yml</h3>

配置在本地或者git
```
spring:
  application:
    name: config-center
  profiles:
    active: native
  cloud:
    config:
      server:
        native:
          searchLocations: classpath:/configs/{profile}
#          searchLocations: file:/d:/configs/{profile}
        git:
          uri: https://gitee.com/zhang.w/cloud-service-configs.git
          default-label: master
          force-pull: true
          searchPaths: '{profile}'
```
通过spring.profiles.active这里可以指定配置文件在本地classpath下,还是在远程git上面，这里默认是放在了本地的classpath下，这里可根据实际项目需求和运维条件进行合理的选择配置方式。

<h3 id="2.3.2">2) {profile}</h3>

上面示例配置代码中的{profile}，是由别的微服务指定的，如用户中心指定配置，用户中心里会有如下配置
cloud-service\user-center\src\main\resources\bootstrap.yml
```
spring:
  application:
    name: user-center
  cloud:
    config:
      discovery:
        enabled: true
        serviceId: config-center
      profile: dev
      fail-fast: true
```

这里的profile: dev就会注入到
```
native:
          searchLocations: classpath:/configs/{profile}
```

配置目录就成了classpath:/configs/dev  ,用户中心启动的时候，就会从配置中心拉取配置，目录就是classpath:/configs/dev/user-center.yml  ,因此用户中心通过配置test或者production等等自定义的字符串，启动时会去找相应的配置，来达到分环境配置的目的，如

- src/main/resources
  - configs
    - dev
    - production
    - test

生产版本我们可以在启动服务```java -jar xxx.jar```时，指定运行环境参数（命令行优先）。

<h3 id="2.3.3">3) 端口</h3>

```
server:
  port: 0
```
这里配置成0，启动时，项目会随机一个端口号。

<h3 id="2.3.4">4) 注册到注册中心</h3>

```
eureka:
  client:
    serviceUrl:
      defaultZone: http://local.register.com:8761/eureka/
```
**注意**，地址后面有个**/eureka/**  。如果是多注册中心，那么通过逗号分隔

<h3 id="2.3.5">5) 注册中心里的显示</h3>

```
server:
  port: 0
eureka:
  client:
    serviceUrl:
      defaultZone: http://local.register.com:8761/eureka/
    registry-fetch-interval-seconds: 5
  instance:
    lease-expiration-duration-in-seconds: 15
    lease-renewal-interval-in-seconds: 5
    prefer-ip-address: true
    instance-id: ${spring.application.name}:${random.int}
```

因为我们是随机端口号，我们这里用了随机数字来显示

| Status |
| :----- |
| UP(2)-[config-center:523766122](http://ip:port/info),[config-center:838191004](http://ip:port/info) |
| UP(1)-[register-center:8761](http://ip:8761/info) |

**注意**: 那个随机数字，并不是真正的端口号，点击跳转到 http://ip:53484/info 之后，我们才能看到真正的端口号。


<h3 id="2.3.6">6) 配置中心底层核心源码</h3>

其原理是通过 config client 发起 http restful 请求到 config server 获取配置信息。（MVC模式）

#### 配置中心底层核心源码 client 端：

- org.springframework.cloud.config
  - client
    - ConfigClientAutoConfiguration.class
    - ConfigClientHealthProperties.class
    - ConfigClientProperties.class
    - ConfigClientStateHolder.class
    - ConfigClientWatch.class
    - ConfigServerHealthIndicator.class
    - ConfigServerInstanceProvider.class
    - ConfigServiceBootstrapConfiguration.class
    - ConfigServicePropertySourceLocator.class
    - DiscoveryClientConfigServiceBootstrapConfiguration.class
    - RetryProperties.class

其中 ConfigServerInstanceProvider.class 里的方法 getConfigServerInstances(String serviceId) 正好与我们的客户端配置的 serviceId 对应。

```
public class ConfigServerInstanceProvider {
    private static Log logger = LogFactory.getLog(ConfigServerInstanceProvider.class);
    private final DiscoveryClient client;

    public ConfigServerInstanceProvider(DiscoveryClient client) {
        this.client = client;
    }

    @Retryable(
        interceptor = "configServerRetryInterceptor"
    )
    public List<ServiceInstance> getConfigServerInstances(String serviceId) {
        logger.debug("Locating configserver (" + serviceId + ") via discovery");
        List<ServiceInstance> instances = this.client.getInstances(serviceId);
        if (instances.isEmpty()) {
            throw new IllegalStateException("No instances found of configserver (" + serviceId + ")");
        } else {
            logger.debug("Located configserver (" + serviceId + ") via discovery. No of instances found: " + instances.size());
            return instances;
        }
    }
}
```

```
  cloud:
    config:
      discovery:
        enabled: true
        serviceId: config-center
      profile: dev
      fail-fast: true
```



#### 配置中心底层核心源码 server 端：

- org.springframework.cloud.config
  - server
      - environment
        - EnvironmentController.class

其中 EnvironmentController.class 里的方法 labelled 正好与我们的客户端发起的请求对应。（可以自己拼接url在浏览器中访问）
```
@RestController
@RequestMapping(
    method = {RequestMethod.GET},
    path = {"${spring.cloud.config.server.prefix:}"}
)
public class EnvironmentController {
  // 省略部分代码

    @RequestMapping({"/{name}/{profiles}/{label:.*}"})
    public Environment labelled(@PathVariable String name, @PathVariable String profiles, @PathVariable String label) {
        if (name != null && name.contains("(_)")) {
            name = name.replace("(_)", "/");
        }

        if (label != null && label.contains("(_)")) {
            label = label.replace("(_)", "/");
        }

        Environment environment = this.repository.findOne(name, profiles, label);
        if (this.acceptEmpty || environment != null && !environment.getPropertySources().isEmpty()) {
            return environment;
        } else {
            throw new EnvironmentNotFoundException("Profile Not found");
        }
    }

     // 省略部分代码
}
```


<h2 id="2.4">2.4 用户中心</h2>

- user-center
  - sql
  - src
    - main
      - java
        - com.cloud.user
          - UserCenterApplication.java
      - resources
        - mybatis-mappers
        - .gitignore
        - bootstrap.yml
    - test
  - .gitignore
  - pom.xml
  - README.md


<h3 id="2.4.1">1) 数据库脚本</h3>

在user-center模块下的sql文件夹下cloud_user.sql里是用户中心的数据脚本，包含建表语句和初始化数据。

<h3 id="2.4.2">2) bootstrap.yml</h3>

```
spring:
  application:
    name: user-center
  cloud:
    config:
      discovery:
        enabled: true
        serviceId: config-center
      profile: dev
      fail-fast: true
server:
  port: 0
eureka:
  client:
    serviceUrl:
      defaultZone: http://local.register.com:8761/eureka/
    registry-fetch-interval-seconds: 5
  instance:
    lease-expiration-duration-in-seconds: 15
    lease-renewal-interval-in-seconds: 5
    prefer-ip-address: true
    instance-id: ${spring.application.name}:${random.int}
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    health:
      show-details: always
```

这里只列出主要配置，配置中心的serviceId就是配置中心的spring.application.name，还有自己的profile，还有注册中心的url。

<h3 id="2.4.3">3) user-center.yml</h3>


cloud-service\config-center\src\main\resources\configs\dev\
* user-center.yml

这里配置了用户系统具体的一些配置，比如数据库、mq、mybatis、日志级别、鉴权等。

#### a) 日志级别和文件配置
```
logging:
  level:
    root: info
    com.cloud: debug
  file: logs/${spring.application.name}.log
```

#### b) 数据源配置
```
spring:
  datasource:
    driver-class-name: com.mysql.jdbc.Driver
    url: jdbc:mysql://local.mysql.com:3306/cloud_user?useUnicode=true&characterEncoding=utf8&autoReconnect=true&allowMultiQueries=true&useSSL=false&serverTimezone=UTC
    username: root
    password: mysql
```

#### c) Rabbitmq 配置
```
  rabbitmq:
    host: local.rabbitmq.com
    port: 5672
    username: cloud-dev
    password: cloud-dev
    virtual-host: /
```

#### d) redis 配置
```
 redis:
    host: local.redis.com
    port: 6379
    password:
    timeout: 10s
```

#### e) Mybatis 配置
```
mybatis:
  type-aliases-package: com.cloud.model.user
  mapper-locations: classpath:/mybatis-mappers/*
  configuration:
    mapUnderscoreToCamelCase: true
```

别名包（type-aliases-package）有多个值的话，逗号隔开。

复杂sql写在mapper.xml文件里，存放路径要与mapper-locations配置的路径对应。

#### f) 鉴权
```
security:
  oauth2:
    resource:
      user-info-uri: http://local.gateway.com:8080/api-o/user-me
      prefer-token-info: false
```

#### g) 微信公众号配置
```
wechat:
  domain: http://api.gateway.com:8080/api-u
  infos:
    app1:
      appid: xxx
      secret: xxx
    app2:
      appid: xxx
      secret: xxx
```
详细看下代码
* cloud-service\user-center\src\main\java\com\cloud\user\service\impl\WechatServiceImpl.java
* cloud-service\manage-backend\src\main\resources\static\pages\wechat\index.html


<h3 id="2.4.4">4) 配置类</h3>
- com.cloud.user
  - config
    - AsycTaskExecutorConfig.java
    - ExceptionHandlerAdvice.java
    - RabbitmqConfig.java
    - ResourceServerConfig.java
    - RestTemplateConfig.java
    - SessionConfig.java
    - SwaggerConfig.java
    - WechatConfig.java

#### a) 全局异常处理
```
@RestControllerAdvice
public class ExceptionHandlerAdvice {

	@ExceptionHandler({IllegalArgumentException.class})
	@ResponseStatus(HttpStatus.BAD_REQUEST)
	public Map<String, Object> badRequestException(IllegalArgumentException exception) {
		Map<String, Object> data = new HashMap<>();
		data.put("code", HttpStatus.BAD_REQUEST.value());
		data.put("message", exception.getMessage());

		return data;
	}
}
```
抛出 java.lang.IllegalArgumentException 异常的接口将返回http状态码400。

#### b) Rabbitmq的exchange声明
```
@Configuration
public class RabbitmqConfig {

	@Bean
	public TopicExchange topicExchange() {
		return new TopicExchange(UserCenterMq.MQ_EXCHANGE_USER);
	}
}
```
这里声明一个topic类型的exchange，发消息时用。

#### c) 资源权限配置
```
@EnableResourceServer
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().exceptionHandling()
                .authenticationEntryPoint(
                        (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and().authorizeRequests()
                .antMatchers(PermitAllUrl.permitAllUrl("/users-anon/**", "/wechat/**")).permitAll() // 放开权限的url
                .anyRequest().authenticated().and().httpBasic();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
```

* ```@EnableResourceServer```将我们的项目作为资源服务器
* ```prePostEnabled = true```是启动权限注解支持
* ```.antMatchers(PermitAllUrl.permitAllUrl("/users-anon/**", "/wechat/**")).permitAll()```这里符合规则的url将不做权限拦截


#### d) 密码加密处理器
```
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
```
声明一个密码加密和校验处理器Bean，该bean是spring security自带的。





<h2 id="2.5">2.5 认证中心</h2>

- oauth-center
  - sql
    - cloud_oauth.sql
  - src
    - main
      - java
        - com.cloud.oauth
          - config
          - controller
          - feign
          - service.impl
          - OAuthCenterApplication.java
      - resources
        - .gitignore
        - bootstrap.yml
  - test
  - .gitignore
  - oauth-center.iml
  - pom.xml
  - README.md

<h3 id="2.5.1">1) 数据库脚本</h3>

在 oauth-center 模块下的 sql 文件夹下 cloud_oauth.sql 里是认证中心的数据脚本，包含建表语句和初始化数据。

<h3 id="2.5.2">2) bootstrap.yml</h3>

除了 spring.application.name 之外，其他配置与用户中心的 bootstrap.yml 相同。

<h3 id="2.5.3">3) oauth-center.yml</h3>

#### a) redis 配置
```
  redis:
    host: local.redis.com
    port: 6379
    password:
```

如redis有密码，与host同层级加节点password。**注意** password 冒号后加一个空格。
```
  redis:
    host: local.redis.com
    port: 6379
    password: aaaa
```

#### b) 数据库配置

```
spring:
  datasource:
    driver-class-name: com.mysql.jdbc.Driver
    url: jdbc:mysql://local.mysql.com:3306/cloud_user?useUnicode=true&characterEncoding=utf8&autoReconnect=true&allowMultiQueries=true&useSSL=false&serverTimezone=UTC
    username: root
    password: mysql
```

#### c) token 是否用 jwt
```
access_token:
  store-jwt: false
  jwt-signing-key: xiao@wei@jia@gou=$==+_+%0%:)(:)
  add-userinfo: false
```

* false 的话 token 是默认的 uuid
* true 的话 token 将采用 jwt

com.cloud.oauth.config.AuthorizationServerConfig.java
```
   /**
     * 使用jwt或者redis<br>
     * 默认redis
     */
    @Value("${access_token.store-jwt:false}")
    private boolean storeWithJwt;

    /**
     * 令牌存储
     */
    @Bean
    public TokenStore tokenStore() {
        if (storeWithJwt) {
            return new JwtTokenStore(accessTokenConverter());
        }
        RedisTokenStore redisTokenStore = new RedisTokenStore(redisConnectionFactory);
        // 2018.08.04添加,解决同一username每次登陆access_token都相同的问题
        redisTokenStore.setAuthenticationKeyGenerator(new RandomAuthenticationKeyGenerator());

        return redisTokenStore;
    }

```

使用jwt时，需要配置这个签名key，具体可看下     com.cloud.oauth.config.AuthorizationServerConfig.java 里面的代码
```
   /**
     * jwt签名key，可随意指定<br>
     * 如配置文件里不设置的话，冒号后面的是默认值
     */
    @Value("${access_token.jwt-signing-key:xiaoweijiagou}")
    private String signingKey;

    /**
     * Jwt资源令牌转换器<br>
     * 参数access_token.store-jwt为true时用到
     *
     * @return accessTokenConverter
     */
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter() {
            @Override
            public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
                OAuth2AccessToken oAuth2AccessToken = super.enhance(accessToken, authentication);
                addLoginUserInfo(oAuth2AccessToken, authentication); // 2018.07.13 将当前用户信息追加到登陆后返回数据里
                return oAuth2AccessToken;
            }
        };
        DefaultAccessTokenConverter defaultAccessTokenConverter = (DefaultAccessTokenConverter) jwtAccessTokenConverter
                .getAccessTokenConverter();
        DefaultUserAuthenticationConverter userAuthenticationConverter = new DefaultUserAuthenticationConverter();
        userAuthenticationConverter.setUserDetailsService(userDetailsService);

        defaultAccessTokenConverter.setUserTokenConverter(userAuthenticationConverter);
        // 2018.06.29 这里务必设置一个，否则多台认证中心的话，一旦使用jwt方式，access_token将解析错误
        jwtAccessTokenConverter.setSigningKey(signingKey);

        return jwtAccessTokenConverter;
    }
```

<h3 id="2.5.4">4) 配置类</h3>

- oauth-center
  - sql
    - cloud_oauth.sql
  - src
    - main
      - java
        - com.cloud.oauth
          - config
            - AuthorizationServerConfig.java
            - PasswordEncoderConfig.java
            - ResourceServerConfig.java
            - SecurityConfig.java
            - SessionConfig.java
            - SwaggerConfig.java

#### a) 授权服务器配置

```
/**
 * 授权服务器配置
 *
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
```

#### b) 资源服务器
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
 * @author 小威老师 xiaoweijiagou@163.com
 *
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
```

#### c) Session共享配置
```
/**
 * 开启session共享
 *
 */
@EnableRedisHttpSession
public class SessionConfig {

}
```
用 redis 做 session 共享，在授权码模式下，可能会涉及参数 code 和 state 和 redirect_url 的传递，多台服务器下需要共享 session 。（目前该项目没用授权码模式，此处不设置也没问题）。





<h2 id="2.6">2.6 文件中心</h2>

- file-center
  - sql
    - cloud_file.sql
  - src
    - main
      - java
        - com.cloud.file
          - config >
          - controller >
          - dao >
          - model >
          - service >
          - utils >
          - FileCenterApplication.java
      - resources
        - mybatis-mappers >
        - .gitignore
        - bootstrap.yml
  - .gitignore
  - file-center.iml
  - pom.xml
  - README.md


<h3 id="2.6.1">1) 数据库脚本</h3>

在 file-center 模块下的 sql 文件夹下 cloud_file.sql 里是认证中心的数据脚本，包含建表语句和初始化数据。

<h3 id="2.6.2">2) bootstrap.yml</h3>

除了 spring.application.name 之外，其他配置与用户中心的 bootstrap.yml 相同。

<h3 id="2.6.3">3) file-center.yml</h3>

#### a) 数据库和 mq
```
spring:
  datasource:
    driver-class-name: com.mysql.jdbc.Driver
    url: jdbc:mysql://local.mysql.com:3306/cloud_file?useUnicode=true&characterEncoding=utf8&autoReconnect=true&allowMultiQueries=true&useSSL=false&serverTimezone=UTC
    username: root
    password: mysql
  rabbitmq:
    host: local.rabbitmq.com
    port: 5672
    username: cloud-dev
    password: cloud-dev
    virtual-host: /
```

#### b) 上传文件大小限制
```
http:
  multipart:
    max-file-size: 100MB
    max-request-size: 100MB
```

#### c) 自定义配置-本地存储文件
```
file:
  local:
    path: D:/localFile
    prefix: /statics
    urlPrefix: http://api.gateway.com:8080/api-f${file.local.prefix}
```

* path 是上传文件存储根路径
* prefix 是前缀
* urlPrefix 是域名加前缀

如 D:/localFile/aaa.png 用url访问就是 http://api.gateway.com:8080/api-f/statics/aaa.png

#### d) 阿里云存储文件
```
  aliyun:
    endpoint: xxx
    accessKeyId: xxx
    accessKeySecret: xxx
    bucketName: xxx
    domain: https://xxx
```

如要上传图片到阿里云，这里需要配置你的阿里云对象存储OSS相关配置，详细根据视频目录看下视频。

<h3 id="2.6.4">4) 配置类</h3>

- file-center
  - sql
    - cloud_file.sql
  - src
    - main
      - java
        - com.cloud.file
          - config
            - AliyunConfig.java
            - ExceptionHandlerAdvice.java
            - FileServiceFactory.java
            - LocalFilePathConfig.java
            - ResourceServerConfig.java
            - SwaggerConfig.java

#### a) 加载jar包外文件
```
/** 使系统加载jar包外的文件 */
@Configuration
public class LocalFilePathConfig {

	/** 上传文件存储在本地的根路径  */
	@Value("${file.local.path}")
	private String localFilePath;

	/**  url前缀  */
	@Value("${file.local.prefix}")
	public String localFilePrefix;

	@Bean
	public WebMvcConfigurer webMvcConfigurerAdapter() {
		return new WebMvcConfigurer() {
			/** 外部文件访问 */
			@Override
			public void addResourceHandlers(ResourceHandlerRegistry registry) {
				registry.addResourceHandler(localFilePrefix + "/**")
						.addResourceLocations(ResourceUtils.FILE_URL_PREFIX + localFilePath + File.separator);
			}
		};
	}
}
```
上传文件存储路径肯定是在jar包外部的，这里不像传统war包是解压成文件夹的，因此这里需要做个静态资源的映射处理。将url前缀和存储路径做了个映射。

#### b) 资源服务器
```
/** 资源服务配置 */
@EnableResourceServer
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

	/**  url前缀  */
	@Value("${file.local.prefix}")
	public String localFilePrefix;

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().exceptionHandling()
				.authenticationEntryPoint(
						(request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
				.and().authorizeRequests()
				.antMatchers(PermitAllUrl.permitAllUrl("/files-anon/**", localFilePrefix + "/**")).permitAll() // 放开权限的url
				.anyRequest().authenticated().and().httpBasic();
	}
}
```
这里要将静态资源下的路径放开权限。








<h2 id="2.7">2.7 网关</h2>

- gateway-zuul
  - src
    - main
      - java
        - com.cloud.gateway
          - config
          - controller
          - feign
          - filter
          - GatewayApplication.java
      - resources
        - .gitignore
        - bootstrap.yml
  - .gitignore
  - gateway-zuul.iml
  - pom.xml
  - README.md

bootstrap.yml 里 spring.application.name 为 gateway-zuul ，其余跟用户中心的一样。

<h3 id="2.7.1">1) gateway-zuul.yml</h3>

#### a) 路由规则
```
zuul:
  ignored-services: '*'
  sensitiveHeaders:
  routes:
    oauth:
      path: /api-o/**
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
```

**sensitiveHeaders** 过滤客户端附带的headers，如：   
sensitiveHeaders: X-ABC   
如果在发请求时带了X-ABC，那么X-ABC不会往下游服务传递。

#### b) 自定义参数
```
cron:
  black-ip: 0 0/5 * * * ?
```
这是个cron定时任务表达式，每5分钟执行一次。

com.cloud.gateway.filter.BlackIPAccessFilter.java
```
	/**
	 * 定时同步黑名单IP
	 */
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

<h3 id="2.7.2">2) 配置类</h3>

- gateway-zuul
  - src
    - main
      - java
        - com.cloud.gateway
          - config
            - CrossDomainConfig.java
            - ExceptionHandlerAdvice.java
            - SecurityConfig.java
            - SwaggerConfig.java


#### a) 跨域配置
```
/**
 * 跨域配置<br>
 * 页面访问域名和后端接口地址的域名不一致时，会先发起一个OPTIONS的试探请求<br>
 * 如果不设置跨域的话，js将无法正确访问接口，域名一致的话，不存在这个问题
 *
 */
@Configuration
public class CrossDomainConfig {

    /**
     * 跨域支持
     *
     * @return
     */
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
只需要在网关层配置，别的微服务不需要配置跨域。

#### b) 异常处理
```
@Slf4j
@RestControllerAdvice
public class ExceptionHandlerAdvice {

	/**
	 * feignClient调用异常，将服务的异常和http状态码解析
	 *
	 * @param exception
	 * @param response
	 * @return
	 */
	@ExceptionHandler({ FeignException.class })
	public Map<String, Object> feignException(FeignException exception, HttpServletResponse response) {
```
这里主要处理FeignException，这个是feignclient调用时的异常，不处理的话将会抛出500服务端异常，这里只是将下游服务的原始http状态码还原。







<h2 id="2.8">2.8 日志组件 log-starter</h2>

- log-starter
  - src
    - main
      - java
        - com.cloud.log.autoconfigure
          - LogAop.java
          - LogAutoConfiguration.java
          - LogMqClient.java
      - resources
        - META-INF
          - spring.factories
          - .gitignore
  - .gitignore
  - log-starter.iml
  - pom.xml

这里是模仿spring boot自动配置写的一个组件，就像spring boot里的各种starter，如
```
		<dependency>
			<groupId>org.mybatis.spring.boot</groupId>
			<artifactId>mybatis-spring-boot-starter</artifactId>
		</dependency>
```
你只需要引入mybatis的starter，和数据源的配置，就可以用mybatis了。


<h3 id="2.8.1">1) spring.factories</h3>

- resources
  - META-INF
    - spring.factories

这里配置自动配置的类。
```
org.springframework.boot.autoconfigure.EnableAutoConfiguration=\
com.cloud.log.autoconfigure.LogAutoConfiguration,\
com.cloud.log.autoconfigure.LogAop
```

<h3 id="2.8.2">2) 使用该组件</h3>

我们这里的log-starter是依赖rabbitmq的，只需要引入
```
	<dependency>
		<groupId>com.cloud</groupId>
		<artifactId>log-starter</artifactId>
		<version>${project.version}</version>
	</dependency>
```
再配置上mq信息，如下的aop类即可生效，就实现了aop日志拦截，将log信息发送到mq队列。
```
/**
 * aop实现日志
 *
 */
@Aspect
public class LogAop {

    private static final Logger logger = LoggerFactory.getLogger(LogAop.class);

    @Autowired
    private AmqpTemplate amqpTemplate;

    /**
     * 环绕带注解 @LogAnnotation的方法做aop
     */
    @Around(value = "@annotation(com.cloud.model.log.LogAnnotation)")
    public Object logSave(ProceedingJoinPoint joinPoint) throws Throwable {
```







<h2 id="2.9">2.9 日志中心</h2>

- log-center
  - sql
    - cloud_log.sql
  - src
    - main
      - java
        - com.cloud.log
          - config >
          - consumer >
          - controller >
          - dao >
          - service >
          - LogCenterApplication.java
      - resources
        - mybatis-mappers >
        - .gitignore
        - bootstrap.yml
    - test >
  - .gitignore
  - log-center.iml
  - pom.xml
  - README.md

bootstrap.yml 里 spring.application.name 为 log-center 其余跟用户中心的一样。


<h3 id="2.9.1">1) log-center.yml</h3>

主要是数据库、mq、mybatis的配置，elasticsearch不是必用的。
```
spring:
  datasource:
    driver-class-name: com.mysql.jdbc.Driver
    url: jdbc:mysql://local.mysql.com:3306/cloud_log?useUnicode=true&characterEncoding=utf8&autoReconnect=true&allowMultiQueries=true&useSSL=false&serverTimezone=UTC
    username: root
    password: mysql
  rabbitmq:
    host: local.rabbitmq.com
    port: 5672
    username: cloud-dev
    password: cloud-dev
    virtual-host: /
    listener:
      simple:
        concurrency: 20
        max-concurrency: 50
mybatis:
  type-aliases-package: com.cloud.model.log
  mapper-locations: classpath:/mybatis-mappers/*
  configuration:
    mapUnderscoreToCamelCase: true
elasticsearch:
  clusterName: elasticsearch
  clusterNodes: 127.0.0.1:9300
```

<h3 id="2.9.2">2) 配置类</h3>

- log-center
  - sql
    - cloud_log.sql
  - src
    - main
      - java
        - com.cloud.log
          - config
            - AsycTaskExecutorConfig.java
            - ElasticSearchConfig.java
            - RabbitmqConfig.java
            - ResourceServerConfig.java
            - SwaggerConfig.java

#### a) 开启异步线程池
```
/**  线程池配置、启用异步 */
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

#### b) 声明队列
```
/** rabbitmq配置 */
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

<h3 id="2.9.3">3) 处理日志消息</h3>

```
/** 从mq队列消费日志数据 */
@Component
@RabbitListener(queues = LogQueue.LOG_QUEUE) // 监听队列
public class LogConsumer {

	private static final Logger logger = LoggerFactory.getLogger(LogConsumer.class);

	@Autowired
	private LogService logService;

	/**  处理消息
	 * @param log
	 */
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
从队列中处理消息，将日志存入数据库。

<h3 id="2.9.4">4) 日志存储 mysql 和 elasticsearch 切换</h3>

- log-center
  - sql >
  - src
    - main
      - java
        - com.cloud.log
          - config >
          - consumer >
          - controller >
          - dao >
          - service
            - impl
              - EsLogServiceImpl.java
              - LogServiceImpl.java

如想存储到 elasticsearch 的话，注释掉 LogServiceImpl 上的 @Primary 和 @Service 。

```
//@Primary
//@Service
public class LogServiceImpl implements LogService {
```
或者将 @Primary移到 EsLogServiceImpl 上面。








<h2 id="2.10">2.10 后台管理系统</h2>

- manage-backend
  - sql
    - cloud_backend.sql
  - src
    - main
      - java
        - com.cloud.backend
          - config >
          - consumer >
          - controller >
          - dao >
          - model >
          - service >
          - ManageBackendApplication.java
      - resources
        - mybatis-mappers >
        - static >
        - .gitignore
        - bootstrap.yml
  - .gitignore
  - manage-backend.iml
  - pom.xml
  - README.md

bootstrap.yml 里 spring.application.name 为 manage-backend 其余跟用户中心的一样。

<h3 id="2.10.1">1) manage-backend.yml</h3>

#### a) 数据库和 mq
```
spring:
  datasource:
    driver-class-name: com.mysql.jdbc.Driver
    url: jdbc:mysql://local.mysql.com:3306/cloud_backend?useUnicode=true&characterEncoding=utf8&autoReconnect=true&allowMultiQueries=true&useSSL=false&serverTimezone=UTC
    username: root
    password: mysql
  rabbitmq:
    host: local.rabbitmq.com
    port: 5672
    username: cloud-dev
    password: cloud-dev
    virtual-host: /
```

#### b) 邮件配置
```
  mail:
    default-encoding: UTF-8
    host: smtp.163.com
    username:
    password:
    protocol: smtp
    test-connection: false
#    properties:
#      mail.smtp.auth: true
```
* 不发邮件的话，请忽略即可。
* 如要使用邮件模块发邮件，请写上正确的 username 和 password ，并且将最后两行的注释配置打开，否则发邮件可能会失败。

163邮箱如何开启POP3/SMTP/IMAP服务？   
http://help.163.com/10/0312/13/61J0LI3200752CLQ.html

<h3 id="2.10.2">2) 消息处理</h3>

```
/**
 * 删除角色时，处理消息
 *
 */
@Slf4j
@Component
@RabbitListener(queues = RabbitmqConfig.ROLE_DELETE_QUEUE)
public class RoleDeleteConsumer {

	@Autowired
	private RoleMenuDao roleMenuDao;

	/**
	 * 接收到删除角色的消息<br>
	 * 删除角色和菜单关系
	 * @param roleId
	 */
	@RabbitHandler
	public void roleDeleteHandler(Long roleId) {
		log.info("接收到删除角色的消息,roleId:{}", roleId);
		try {
			roleMenuDao.delete(roleId, null);
		} catch (Exception e) {
			log.error("角色删除消息处理异常", e);
		}
	}
}
```
用户系统删除角色时，会抛消息，后台系统将接收该消息，删除菜单与角色的关系。

<h3 id="2.10.3">3) 静态资源</h3>

- resources
  - static
    - css >
    - fonts >
    - img >
    - js >
    - layui >
    - pages >
    - index.html
    - login.html
    - login-sms.html
    - .gitignore
    - bootstrap.yml

该目录的静态文件和页面是后台管理服务一部分，可单独拿出来部署。

- js
  - bootstrap >
  - libs >
  - my >
  - plugin >
  - constant.js
  - jq.js
  - main.js

constant.js 里定义了一个常量
```
// 我们这里demo是直接访问网关的，因此domainName配置的是后端java服务网关层的域名和端口，
// 正式生产为了保证网关的高可用性，肯定是部署了多个网关服务，然后用nginx反向代理的
// 那么多个网关服务或者生产环境的话，我们这里配置的是nginx的地址
var domainName = "http://api.gateway.com:8080";
```




