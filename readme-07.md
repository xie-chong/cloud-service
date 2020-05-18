# <p align="center">数据库连接池</p>

- [1. 默认连接池](#1)   
- [2. 切换为druid连接池](#2)   
  - [2.1 pom中添加druid依赖](#2.1)   
  - [2.2 修改配置文件](#2.2)   
  - [2.3 修改PermitAllUrl](#2.3)   



---

---

---


---
<h1 id="1">2. 切换为druid连接池</h1>

---

Spring boot2 默认用的数据源连接池是hikari，我也没怎么听过，想了解更多的话，百度关键词 **spring boot2 hikari**


拿用户中心举例，别的服务也一样道理。如user-center.yml，如下所示：   
```
spring:
  datasource:
    driver-class-name: com.mysql.jdbc.Driver
    url: jdbc:mysql://local.mysql.com:3306/cloud_user?useUnicode=true&characterEncoding=utf8&autoReconnect=true&allowMultiQueries=true&useSSL=false&serverTimezone=UTC
    username: root
    password: mysql
    hikari:
      minimum-idle: 5
      maximum-pool-size: 20
      connection-test-query: SELECT 1
```

里面配置了连接池的信息，这里只是配置了几个参数，更多的参数可看下源码。

D:\Software\xiechong-repository\com\zaxxer\HikariCP\2.7.9\HikariCP-2.7.9.jar!\com\zaxxer\hikari\HikariConfig.class
```
public class HikariConfig implements HikariConfigMXBean {
    private static final Logger LOGGER = LoggerFactory.getLogger(HikariConfig.class);
    private static final char[] ID_CHARACTERS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
    private static final long CONNECTION_TIMEOUT;
    private static final long VALIDATION_TIMEOUT;
    private static final long IDLE_TIMEOUT;
    private static final long MAX_LIFETIME;
    private static final int DEFAULT_POOL_SIZE = 10;
    private static boolean unitTest;
    private volatile long connectionTimeout;
    private volatile long validationTimeout;
    private volatile long idleTimeout;
    private volatile long leakDetectionThreshold;
    private volatile long maxLifetime;
    private volatile int maxPoolSize;
    private volatile int minIdle;
    private volatile String username;
    private volatile String password;
    private long initializationFailTimeout;
    private String catalog;
    private String connectionInitSql;
    private String connectionTestQuery;
    private String dataSourceClassName;
    private String dataSourceJndiName;
    private String driverClassName;
    private String jdbcUrl;
    private String poolName;
    private String schema;
    private String transactionIsolationName;
    private boolean isAutoCommit;
    private boolean isReadOnly;
    private boolean isIsolateInternalQueries;
    private boolean isRegisterMbeans;
    private boolean isAllowPoolSuspension;
    private DataSource dataSource;
    private Properties dataSourceProperties;
    private ThreadFactory threadFactory;
    private ScheduledExecutorService scheduledExecutor;
    private MetricsTrackerFactory metricsTrackerFactory;
    private Object metricRegistry;
    private Object healthCheckRegistry;
    private Properties healthCheckProperties;
    private volatile boolean sealed;

    public HikariConfig() {
        this.dataSourceProperties = new Properties();
        this.healthCheckProperties = new Properties();
        this.minIdle = -1;
        this.maxPoolSize = -1;
        this.maxLifetime = MAX_LIFETIME;
        this.connectionTimeout = CONNECTION_TIMEOUT;
        this.validationTimeout = VALIDATION_TIMEOUT;
        this.idleTimeout = IDLE_TIMEOUT;
        this.initializationFailTimeout = 1L;
        this.isAutoCommit = true;
        String systemProp = System.getProperty("hikaricp.configurationFile");
        if (systemProp != null) {
            this.loadProperties(systemProp);
        }

    }
	
	// ......
```

该类的成员变量就是参数，驼峰和中划线效果相同。




---
<h1 id="2">2. 切换为druid连接池</h1>

---

---
<h2 id="2.1">2.1 pom中添加druid依赖</h2>

---

首先为我们的微服务添加druid的pom依赖，只给用到数据库的微服务添加即可，如用户服务、认证中心、管理后台、文件中心、通知中心、日志中心.

```
<dependency>
   <groupId>com.alibaba</groupId>
   <artifactId>druid-spring-boot-starter</artifactId>
   <version>1.1.9</version>
</dependency>
```



---
<h2 id="2.2">2.2 修改配置文件</h2>

---

修改配置，添加druid的配置，主要是连接池的配置参数，可全局搜下，如搜索```driver-class-name: com.mysql.jdbc.Driver```

搜索到的文件都涉及到了数据库的配置，将我们的数据库配置改为如下所示（注意下格式，我们是yml格式的，主要注意层次关系）。

```
druid:
  initialSize: 5
  minIdle: 5
  maxActive: 20
  maxWait: 60000
  timeBetweenEvictionRunsMillis: 60000
  minEvictableIdleTimeMillis: 300000
  validationQuery: SELECT 1
  testWhileIdle: true
  testOnBorrow: true
  testOnReturn: false
  poolPreparedStatements: true
  maxPoolPreparedStatementPerConnectionSize: 20
  filters: stat,wall
  connectionProperties: druid.stat.mergeSql=true;druid.stat.slowSqlMillis=5000
  stat-view-servlet:
    allow: 127.0.0.1 # 仅允许该IP访问，不做此限制的话，配置为空即可

```






---
<h2 id="2.3">2.3 修改PermitAllUrl</h2>

---

cloud-service\commons\src\main\java\com\cloud\common\constants\PermitAllUrl.java

```
/**  需要放开权限的url */
public final class PermitAllUrl {

    /**  监控中心和swagger需要访问的url */
    private static final String[] ENDPOINTS = {"/actuator/health", "/actuator/env", "/actuator/metrics/**", "/actuator/trace", "/actuator/dump",
            "/actuator/jolokia", "/actuator/info", "/actuator/logfile", "/actuator/refresh", "/actuator/flyway", "/actuator/liquibase",
            "/actuator/heapdump", "/actuator/loggers", "/actuator/auditevents", "/actuator/env/PID", "/actuator/jolokia/**",
            "/v2/api-docs/**", "/swagger-ui.html", "/swagger-resources/**", "/webjars/**"};

	// ......

```

在这个类里加上```"/druid/**"```，如下所示

```
/**  需要放开权限的url */
public final class PermitAllUrl {

    /**  监控中心和swagger需要访问的url */
    private static final String[] ENDPOINTS = {"/actuator/health", "/actuator/env", "/actuator/metrics/**", "/actuator/trace", "/actuator/dump",
            "/actuator/jolokia", "/actuator/info", "/actuator/logfile", "/actuator/refresh", "/actuator/flyway", "/actuator/liquibase",
            "/actuator/heapdump", "/actuator/loggers", "/actuator/auditevents", "/actuator/env/PID", "/actuator/jolokia/**",
            "/v2/api-docs/**", "/swagger-ui.html", "/swagger-resources/**", "/webjars/**", "/druid/**"};

	// ......

```

这里主要是druid提供了界面，我们要放开这个权限，访问的话，这里就要单个服务单独访问了，比如用户中心ip和端口号是localhost:7777，那访问链接就是http:// localhost:7777/druid/











