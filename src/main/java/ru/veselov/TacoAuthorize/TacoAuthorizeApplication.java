package ru.veselov.TacoAuthorize;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.veselov.TacoAuthorize.model.User;
import ru.veselov.TacoAuthorize.repository.UserRepository;

@SpringBootApplication
public class TacoAuthorizeApplication {

	public static void main(String[] args) {
		SpringApplication.run(TacoAuthorizeApplication.class, args);
	}


	/*Загрузка в БД юзеров по умолчанию*/
	@Bean
	public ApplicationRunner dataLoader(UserRepository repository, PasswordEncoder encoder){
		return args -> {
			repository.save(new User("Vasya", encoder.encode("pass"), "ROLE_ADMIN"));
			repository.save(new User("Petya", encoder.encode("pass"), "ROLE_ADMIN"));
		};
	}
}
