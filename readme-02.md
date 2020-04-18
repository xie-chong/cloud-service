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

<h3 id="2.4.3">2) bootstrap.yml</h3>

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






