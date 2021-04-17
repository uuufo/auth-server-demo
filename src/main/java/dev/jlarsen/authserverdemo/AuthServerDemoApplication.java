package dev.jlarsen.authserverdemo;

import dev.jlarsen.authserverdemo.models.AuthClient;
import dev.jlarsen.authserverdemo.models.RoleEntity;
import dev.jlarsen.authserverdemo.models.UserEntity;
import dev.jlarsen.authserverdemo.repositories.AuthClientRepository;
import dev.jlarsen.authserverdemo.repositories.RoleRepository;
import dev.jlarsen.authserverdemo.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.*;

@SpringBootApplication
public class AuthServerDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServerDemoApplication.class, args);
	}

	@Bean
	public CommandLineRunner loadInitialData(AuthClientRepository authClientRepository, RoleRepository roleRepository,
											 UserRepository userRepository, PasswordEncoder passwordEncoder) {
		return (args) -> {

			if (((Collection<RoleEntity>)roleRepository.findAll()).size() == 0) {
				roleRepository.save(new RoleEntity("ADMIN"));
//				roleRepository.save(new RoleEntity("USER"));
			}

			if (((Collection<UserEntity>)userRepository.findAll()).size() == 0) {
				userRepository.save(new UserEntity("Test User", "test@email.com", passwordEncoder.encode("12345678"),
						new HashSet<>(Collections.singletonList(new RoleEntity("USER")))));
			}

			if (((Collection<AuthClient>)authClientRepository.findAll()).size() == 0) {
				authClientRepository.save(new AuthClient(
						"test-client",
						"1fWPF19vFOdS0b88QQPCxgfpctSot078",
						passwordEncoder.encode("1fWPF19vFOdS0b88QQPCxgfpctSot078"),
						"http://localhost:8080/login/oauth2/code/auth-client",
						new ArrayList<>(Arrays.asList("read:transactions", "test:scope", "a:scope")),
						new HashMap<>(Collections.singletonMap("accountNo", "5000")),
						new ArrayList<>(Collections.singleton("code")),
						"Test Client 1",
						userRepository.findByEmail("test@email.com"),
						""));
			}



		};
	}

}
