package ru.veselov.TacoAuthorize.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)//гарантирует что если будут определены другие бины такого же типа
    //то данный компонент будет иметь приоритет над ними
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
        throws Exception {
        OAuth2AuthorizationServerConfiguration//репозиторий клиентов, которые могут запрашивать
                // авторизацию от имени пользователей //TODO почитать подробней
                .applyDefaultSecurity(http);
        return http
                .formLogin(Customizer.withDefaults())//TODO почитать подробней
                .build();
    }

    /*Отсюда мы получаем сведения о клиентах, здесь реализуем репозиторий в памяти*/
    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder encoder){
        RegisteredClient registeredClient=
                RegisteredClient.withId(UUID.randomUUID().toString())//случайный идентификатор
                        .clientId("taco-admin-client")//имя клиента (аналог имени пользователя)
                        .clientSecret(encoder.encode("secret"))//пароль
                        .clientAuthenticationMethod(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                        )
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)//используется код авторизации
                        //и токен обновления
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        //зарегистрированные адреса куда будет перенаправлен клиент после предоставления авторизации
                        .redirectUri("http://127.0.0.1:9090/login/oauth2/code/taco-admin-client")
                        //области действия авторизации OAUTH
                        .scope("writeIngredients")
                        .scope("deleteIngredients")
                        .scope(OidcScopes.OPENID)
                        .clientSettings(clientSettings -> {
                            clientSettings.requireUserConsent(true);//здесь мы запрашиваем явного согласия перед предоставлением доступа
                        }).build();


        return new InMemoryRegisteredClientRepository(registeredClient);
    }
    /*Бины для создания Json web Key JWK
    * Создаются пары ключей по 2048 бит, которыми будут подписываться ключи
    * Токен подписывается закрытым ключом, но для проверки достоверности нужно получить открытый ключ
    * с сервера авторизации*/
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException{
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector,securityContext)->
            jwkSelector.select(jwkSet);
    }
    private static RSAKey generateRsa() throws NoSuchAlgorithmException{
        KeyPair keyPair = AuthorizationServerConfig.generateRsaKey();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(rsaPublicKey).privateKey(rsaPrivateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }
    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource){
        return  OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }







}
