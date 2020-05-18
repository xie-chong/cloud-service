# <p align="center">ziokin 追踪</p>

- [1. Zipkin下载](#1)   
  - [1.1 官网](#1.1)   
  - [1.2 下载](#1.2)   
- [2. 运行zipkin](#2)   
  - [2.1 内存InMomory存储数据](#2.1)   
  - [2.2 数据库mysql存储数据](#2.2)   
  - [2.3 Elasticsearch存储数据](#2.3)   
- [3. 代码里配置zipkin](#3)   
  - [3.1 Pom添加依赖](#3.1)   
  - [3.2 配置zipkin地址](#3.2)   
  - [3.3 统计比率设置](#3.3)   
- [4. Zipkin源码配置文件地址](#4)   
- [5. Zipkin数据收集方式](#5)   
  - [5.1 http方式收集](#5.1)   
  - [5.2 Rabbitmq的方式收集](#5.2)   
    - [1)	Zipkin服务端参数变动](#5.2.1)   
    - [2)	客户端参数修改](#5.2.2)   


---

---

---


---
<h1 id="1">1. Zipkin下载</h1>

---

---
<h2 id="1.1">1.1 官网</h2>

---

https://zipkin.io/


---
<h2 id="1.2">1.2 下载</h2>

---

https://zipkin.io/pages/quickstart.html   

>**Java**
>If you have Java 8 or higher installed, the quickest way to get started is to fetch the latest release as a self-contained executable jar:
>```
curl -sSL https://zipkin.io/quickstart.sh | bash -s
java -jar zipkin.jar
```

zipkin官方源码的github地址: https://github.com/openzipkin/zipkin   
打开这个网址，往下翻，在Quick-start里面，点击一下 latest released server ，点击后，将会下载一个可执行的jar，可理解为就像我们的spring boot项目打成的jar。

配置文件路径: zipkin/zipkin-server/src/main/resources/zipkin-server-shared.yml   



---
<h1 id="2">2. 运行zipkin</h1>

---

Zipkin支持内存、mysql、elasticsearch等存储数据，采用一种方式运行即可，以下将简单说明运行方式。
如上章节下载的jar文件名为zipkin-server-2.21.1-exec.jar,目前这是最新版本，以后可能版本会升级，自行下载最新版即可，以下内容将以该文件名为例



---
<h2 id="2.1">2.1 内存InMomory存储数据</h2>

---

Zipkin默认采用内存存储数据，重启后数据就没了，而且内存存储数量有限

**启动命令**   
```
java –jar zipkin-server-2.21.1-exec.jar
```

默认端口号为9411

http://localhost:9411

如要指定端口号，用参数QUERY_PORT，详细解读看下源码里面的配置文件   
```
java -jar zipkin-server-2.21.1-exec.jar --QUERY_PORT=9411
```






---
<h2 id="2.2">2.2 数据库mysql存储数据</h2>

---

首先要初始化一些表，默认库名zipkin，建表语句请点击查看[《readme-05.md》](readme-05.md)

**启动命令**   
```
java -jar zipkin-server-2.21.1-exec.jar --QUERY_PORT=9411 --STORAGE_TYPE=mysql --MYSQL_HOST=localhost --MYSQL_TCP_PORT=3306 --MYSQL_USER=root --MYSQL_PASS=root --MYSQL_DB=zipkin
```

数据库ip、端口号、用户名、密码、库名等都可以指定，智慧如你，相信一眼就能识别出是哪个配置了。
如zipkin端口号是参数QUERY_PORT来指定；Mysql端口号参数是MYSQL_TCP_PORT来指定；库名参数是MYSQL_DB来指定（详细看视频）。





---
<h2 id="2.3">2.3 Elasticsearch存储数据</h2>

---

Es存储的话，只需要用启动命令即可。首先你要启动了elasticsearch，不要犯这种低级错哦。

**启动命令**   
```
java -jar zipkin-server-2.8.3-exec.jar --QUERY_PORT=9411 --STORAGE_TYPE=elasticsearch --ES_HOSTS=http://localhost:9200 --ES_INDEX=zipkin
```

索引名参数是ES_INDEX来指定；测试发现，实际index，并不是zipkin，而是zipkin:span-2020-05-18，应该是按日期分index了。






---
<h1 id="3">3. 代码里配置zipkin</h1>

---

---
<h2 id="3.1">3.1 Pom添加依赖</h2>

---

在我们需要使用 zipkin 跟踪的项目里添加zipkin依赖，如用户系统、授权系统、网关系统、后台管理系统、通知系统、文件系统、日志系统等。

```
<dependency>
   <groupId>org.springframework.cloud</groupId>
   <artifactId>spring-cloud-starter-zipkin</artifactId>
   <version>${starter-zipkin.version}</version>
</dependency>
```

版本号在父pom里统一定义。




---
<h2 id="3.2">3.2 配置zipkin地址</h2>

---

如我们启动的zipkin端口号是9411；地址是http://localhost:9411；我们需要在用到zipkin的项目里配置这个地址 spring.zipkin.base-url=http://localhost:9411

```
spring:
  zipkin:
    base-url: http://localhost:9411
    enabled: true
    sender:
      type: web
```





---
<h2 id="3.3">3.3 统计比率设置</h2>

---

Zipkin默认是只收集0.1比率的数据的，这个参数可以修改，是由客户端调用者自己来设置的，这里注意下，不是zipkin服务端，是客户端，如用户系统参数是```spring.sleuth.sampler.percentage=0.1```

源码类是 org.springframework.cloud.sleuth.sampler.SamplerProperties，这个参数我们源码里没有配置，将默认采用0.1，如要修改的话，你可自行添加该参数到配置文件里，如下所示

```
spring:
  zipkin:
    base-url: http://localhost:9411
    enabled: true
    sender:
      type: web
  sleuth:
    sampler:
      percentage: 0.1
```

取值范围是0-1，如改成1的话，将收集全部请求。





---
<h1 id="4">4. Zipkin源码配置文件地址</h1>

---

https://github.com/openzipkin/zipkin/blob/master/zipkin-server/src/main/resources/zipkin-server-shared.yml

其实运行时，指定的参数都是从这个源码配置里查到的.

如端口号参数QUERY_PORT
```
server:
  port: ${QUERY_PORT:9411}
  use-forward-headers: true
```

如mysql参数
```
 mysql:
      jdbc-url: ${MYSQL_JDBC_URL:}
      host: ${MYSQL_HOST:localhost}
      port: ${MYSQL_TCP_PORT:3306}
      username: ${MYSQL_USER:}
      password: ${MYSQL_PASS:}
      db: ${MYSQL_DB:zipkin}
      max-active: ${MYSQL_MAX_CONNECTIONS:10}
      use-ssl: ${MYSQL_USE_SSL:false}
```

如elasticsearch参数
```
elasticsearch:
      # host is left unset intentionally, to defer the decision
      hosts: ${ES_HOSTS:}
      pipeline: ${ES_PIPELINE:}
      timeout: ${ES_TIMEOUT:10000}
      index: ${ES_INDEX:zipkin}
      ensure-templates: ${ES_ENSURE_TEMPLATES:true}
      date-separator: ${ES_DATE_SEPARATOR:-}
      index-shards: ${ES_INDEX_SHARDS:5}
      index-replicas: ${ES_INDEX_REPLICAS:1}
      username: ${ES_USERNAME:}
      password: ${ES_PASSWORD:}
      credentials-file: ${ES_CREDENTIALS_FILE:}
      credentials-refresh-interval: ${ES_CREDENTIALS_REFRESH_INTERVAL:5}
      http-logging: ${ES_HTTP_LOGGING:}
      health-check:
        enabled: ${ES_HEALTH_CHECK_ENABLED:true}
        interval: ${ES_HEALTH_CHECK_INTERVAL:3s}
```






---
<h1 id="5">5. Zipkin数据收集方式</h1>

---

看了源码的配置文件之后，可以发现默认是http的方式收集数据的。

```
zipkin:
  self-tracing:
    # Set to true to enable self-tracing.
    enabled: ${SELF_TRACING_ENABLED:false}
    # percentage of self-traces to retain. If set to a value other than 1.0, traces-per-second will
    # not be used.
    sample-rate: ${SELF_TRACING_SAMPLE_RATE:1.0}
    # Number of traces per second to retain. sample-rate must be set to 1.0 to use this value. If
    # set to 0, an unlimited number of traces per second will be retained.
    traces-per-second: ${SELF_TRACING_TRACES_PER_SECOND:1}
    # Timeout in seconds to flush self-tracing data to storage.
    message-timeout: ${SELF_TRACING_FLUSH_INTERVAL:1}
  collector:
    # percentage to traces to retain
    sample-rate: ${COLLECTOR_SAMPLE_RATE:1.0}
    activemq:
      enabled: ${COLLECTOR_ACTIVEMQ_ENABLED:true}
      # ActiveMQ broker url. Ex. tcp://localhost:61616 or failover:(tcp://localhost:61616,tcp://remotehost:61616)
      url: ${ACTIVEMQ_URL:}
      # Queue from which to collect span messages.
      queue: ${ACTIVEMQ_QUEUE:zipkin}
      # Number of concurrent span consumers.
      concurrency: ${ACTIVEMQ_CONCURRENCY:1}
      # Optional username to connect to the broker
      username: ${ACTIVEMQ_USERNAME:}
      # Optional password to connect to the broker
      password: ${ACTIVEMQ_PASSWORD:}
    http:
      # Set to false to disable creation of spans via HTTP collector API
      enabled: ${COLLECTOR_HTTP_ENABLED:${HTTP_COLLECTOR_ENABLED:true}}
```

我们以上的配置和运行也是基于发送http请求的。






---
<h2 id="5.1">5.1 http方式收集</h2>

---

运行zipkin的服务zipkin-server-2.21.1-exec.jar参数命令，如第二章节的一样，我们的各个微服务客户端的参数是:   
```
spring:
  zipkin:
    base-url: http://localhost:9411
    enabled: true
    sender:
      type: web
```

以上章节已经说明，这里不再过多说。





---
<h2 id="5.2">5.2 Rabbitmq的方式收集</h2>

---

---
<h3 id="5.2.1">1)	Zipkin服务端参数变动</h3>

---

运行zipkin的服务zipkin-server-2.21.1-exec.jar参数命令，需要添加mq的参数，注意**参数间不要有换行符**，否则相当于回车键，就运行了。

```
    rabbitmq:
      enabled: ${COLLECTOR_RABBITMQ_ENABLED:true}
      # RabbitMQ server address list (comma-separated list of host:port)
      addresses: ${RABBIT_ADDRESSES:}
      concurrency: ${RABBIT_CONCURRENCY:1}
      # TCP connection timeout in milliseconds
      connection-timeout: ${RABBIT_CONNECTION_TIMEOUT:60000}
      password: ${RABBIT_PASSWORD:guest}
      queue: ${RABBIT_QUEUE:zipkin}
      username: ${RABBIT_USER:guest}
      virtual-host: ${RABBIT_VIRTUAL_HOST:/}
      useSsl: ${RABBIT_USE_SSL:false}
      uri: ${RABBIT_URI:}
```

Mq地址   
```
    rabbitmq:
      enabled: ${COLLECTOR_RABBITMQ_ENABLED:true}
      # RabbitMQ server address list (comma-separated list of host:port)
      addresses: ${RABBIT_ADDRESSES:}
```

```
-- RABBIT_ADDRESSES=localhost:5672
```

http方式需要修改为false（该参数要注入false）   
```
    http:
      # Set to false to disable creation of spans via HTTP collector API
      enabled: ${COLLECTOR_HTTP_ENABLED:${HTTP_COLLECTOR_ENABLED:true}}
```

**我们以mq 用户名:cloud-dev 密码:cloud-dev Virtual host为/举例**

**如内存存储**

```
java -jar zipkin-server-2.8.3-exec.jar --QUERY_PORT=9411 --HTTP_COLLECTOR_ENABLED=false --RABBIT_ADDRESSES=localhost:5672 --RABBIT_USER=cloud-dev --RABBIT_PASSWORD=cloud-dev --RABBIT_VIRTUAL_HOST=/
```

**mysql存储**

```
java -jar zipkin-server-2.8.3-exec.jar --QUERY_PORT=9411 --STORAGE_TYPE=mysql --MYSQL_HOST=localhost --MYSQL_TCP_PORT=3306 --MYSQL_USER=root --MYSQL_PASS=root --MYSQL_DB=zipkin --HTTP_COLLECTOR_ENABLED=false --RABBIT_ADDRESSES=localhost:5672 --RABBIT_USER=cloud-dev --RABBIT_PASSWORD=cloud-dev --RABBIT_VIRTUAL_HOST=/
```


**elasticsearch存储**

```
java -jar zipkin-server-2.8.3-exec.jar --QUERY_PORT=9411 --STORAGE_TYPE=elasticsearch --ES_HOSTS=http://localhost:9200 --ES_INDEX=zipkin --HTTP_COLLECTOR_ENABLED=false --RABBIT_ADDRESSES=localhost:5672 --RABBIT_USER=cloud-dev --RABBIT_PASSWORD=cloud-dev --RABBIT_VIRTUAL_HOST=/
```

**其实就是在第二章的参数基础上加上**

```
--HTTP_COLLECTOR_ENABLED=false --RABBIT_ADDRESSES=localhost:5672 --RABBIT_USER=cloud-dev --RABBIT_PASSWORD=cloud-dev --RABBIT_VIRTUAL_HOST=/
```

当然为了方便，我们也可以把它写成脚本。





---
<h3 id="5.2.2">2)	客户端参数修改</h3>

---

1. 客户端要添加rabbitmq依赖

```
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-amqp</artifactId>
</dependency>
```

我们的微服务gateway-zuul和oauth-center暂时未添加mq依赖，需要在这两个服务的pom文件里添加依赖。别的服务因为引入了log-stater，log-stater里已经引入了rabbitmq，因此别的服务pom不需要改动。


2. 配置参数需要修改

我们默认的在配置中心，各个微服务里

```
spring:
  zipkin:
    base-url: http://localhost:9411
    enabled: true
    sender:
      type: web
```

需要修改成 

```
spring:
  zipkin:
    enabled: true
    sender:
      type: rabbit
```

**即去掉了http方式的url，同时把sender type改为rabbit**

源码请看 org.springframework.cloud.sleuth.zipkin2.sender.ZipkinSenderProperties

