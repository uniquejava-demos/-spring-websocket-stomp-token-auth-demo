In my [previous demo](https://github.com/uniquejava-demos/spring-websocket-stomp-cookie-auth-demo002), I used cookie
based authentication for spring websocket, in this demo, we will use stateless token(JWT) based authentication.

## Environment

- Java 17
- Spring Boot 2.7.4
- React 18.2.0

## Notes

### 配置http.oauth2ResourceServer（jwt）以后

1. 获得了免费的 `/logout` endpoint, 但是调用他并不会让jwt token失效，it's useless.
2. 获得了免费的 BearerTokenAuthenticationFilter

### 认证方式1: 通过query url传token (not recommended)

因为通过url传递token极不安全， 在此仅做参考。

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

### 认证方式2: 在CONNECT阶段通过Stomp header 传token (recommended)

这种方式被spring官方文档推荐： https://docs.spring.io/spring-framework/docs/current/reference/html/web.html#websocket-stomp-authentication-token-based

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
