package demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

@SpringBootApplication
public class SpringWebsocketStompTokenAuthDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringWebsocketStompTokenAuthDemoApplication.class, args);
    }

    @Bean
    public KeyPair keyPair() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
