# <p align="center">模块详细介绍和配置</p>

- [1丨项目结构](#1)   
- [2丨模块和配置](#2)   
  - [2-1. 父pom.xml](#2-1)   
  - [2-2. 注册中心](#2-2)   





---
---
---
<h2 id="1">1丨项目结构</h2>

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
<h2 id="2">2丨模块和配置</h2>

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


<h3 id="2-1">2-1. 父pom.xml</h3>

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


<h3 id="2-2">2-2. 注册中心</h3>



