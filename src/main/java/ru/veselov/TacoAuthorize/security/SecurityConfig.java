package ru.veselov.TacoAuthorize.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import ru.veselov.TacoAuthorize.repository.UserRepository;

@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurity(HttpSecurity httpSecurity) throws Exception{
        return  httpSecurity
                .authorizeHttpRequests( authorizeRequest ->
                        authorizeRequest.anyRequest().authenticated())
                .formLogin()
                .and().build();
    }


    @Bean
    UserDetailsService userDetailsService(UserRepository userRepository){
        return userRepository::findByUsername;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
