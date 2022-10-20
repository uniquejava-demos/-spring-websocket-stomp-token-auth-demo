In my [previous demo](https://github.com/uniquejava-demos/spring-websocket-stomp-cookie-auth-demo002), I used cookie
based authentication for spring websocket, in this demo, we will use stateless token(JWT) based authentication.

## Environment

- Java 17
- Spring Boot 2.7.4
- React 18.2.0


## 配置http.oauth2ResourceServer（jwt）以后

1. 获得了免费的 `/logout` endpoint, 但是调用他并不会让jwt token失效，it's useless.
2. 获得了免费的 BearerTokenAuthenticationFilter

## 认证方式1: 通过query url传token (not recommended)

因为通过url传递token极不安全， 在此仅做参考, 相应代码在分支: https://github.com/uniquejava-demos/spring-websocket-stomp-token-auth-demo006/tree/pass-token-by-url 上。

stomp.js前端:

```js
const token = sessionStorage.getItem("access_token");
const client = new Client({
    brokerURL: `ws://localhost:8080/stomp?access_token=${token}`,

    // https://docs.spring.io/spring-framework/docs/4.3.x/spring-framework-reference/html/websocket.html#websocket-stomp-handle-broker-relay-configure
    // The STOMP broker relay always sets the login and passcode headers on every CONNECT frame that it forwards to the broker on behalf of clients.
    // Therefore WebSocket clients need not set those headers; they will be ignored.
    connectHeaders: {
        // login: 'user',
        // passcode: 'password',
    },
    debug: function (str) {
        console.log(str)
    }
}
```

SecurityConfig.java 后端:

```java
http.oauth2ResourceServer(rs->{
  val tokenResolver=new DefaultBearerTokenResolver();
  tokenResolver.setAllowUriQueryParameter(true);

  rs.bearerTokenResolver(tokenResolver);

  rs.jwt();
 })
```

## 认证方式2: 在CONNECT阶段通过Stomp header 传token (recommended)

这种方式被spring官方文档推荐： https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#websocket-stomp-authentication-token-based

前端:

```js
const client = new Client({
    brokerURL: `ws://localhost:8080/stomp`,
    connectHeaders: {
      "access_token": token
    }
})
```

后端:

我们自己在InboundChannelInterceptor中处理用户登录， 所以我们需要设置ws的端点 `/stomp`为permitAll

```java
http
    .authorizeHttpRequests((authorize) -> authorize
    .antMatchers("/stomp").permitAll()
```

接下来，我们需要调用AuthenticationManager处理用户的Bearer Token.

spring security 5.7 以后如何expose AuthenticationManager.

https://stackoverflow.com/questions/71281032/spring-security-exposing-authenticationmanager-without-websecurityconfigureradap

```java
@Bean
public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) {
  return authenticationConfiguration.getAuthenticationManager();
}
```
No luck!

When connect to websocket, it throws this error.

> No AuthenticationProvider found for BearerTokenAuthenticationToken

Per my previous experience, I then tried the following code, it works like charm!

```java
 @Bean
 public AuthenticationManager authenticationManager(JwtDecoder jwtDecoder) {
     JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
     return new ProviderManager(jwtAuthenticationProvider);
 }
```

Use this AuthenticationManager to process our access_token.

```java
if (StompCommand.CONNECT == accessor.getCommand()) {
    MessageHeaders headers = message.getHeaders();

    // JwtAuthenticationToken auth = (JwtAuthenticationToken) headers.get("simpUser");
    // log.info("auth.name: {}", auth.getName());
    String token = accessor.getFirstNativeHeader("access_token");
    log.info("token: {}", token);

    JwtAuthenticationToken user =  (JwtAuthenticationToken) authenticationManager.authenticate(new BearerTokenAuthenticationToken(token));
     log.info("simpUser: {}", user);
     log.info("name: {}", user.getName());
     log.info("token.subject: {}", user.getToken().getSubject());
    accessor.setUser(user);
}
```

Log.

```java
demo.config.WebSocketConfig  : simpUser: JwtAuthenticationToken [Principal=org.springframework.security.oauth2.jwt.Jwt@2b6a6cdc, Credentials=[PROTECTED], Authenticated=true, Details=null, Granted Authorities=[SCOPE_app]]
demo.config.WebSocketConfig  : name: cyper
demo.config.WebSocketConfig  : token.subject: cyper
```

## JWT token的缺点

在这种情况下simpUser是一个JwtAuthenticationToken对象

```java
if(StompCommand.CONNECT==accessor.getCommand()){
  log.info("=============== CONNECT =============");
  MessageHeaders headers=message.getHeaders();
  JwtAuthenticationToken auth=(JwtAuthenticationToken)headers.get("simpUser");
}
```

他的缺点很明显

1. 无法revoke, 但是从[这里](BearerTokenAuthenticationFilter)我获得了一个灵感: 在logout success
   handler里更换server端的rsa key。
2. 我觉得这个做法不靠谱， 替换key会导致所有的jwt token失效，并非单个user。
3. 还是需要配合redis。
