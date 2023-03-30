package com.tutorial.authorizationserver;

import com.tutorial.authorizationserver.entity.Role;
import com.tutorial.authorizationserver.enums.RoleName;
import com.tutorial.authorizationserver.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthorizationServerApplication /*implements CommandLineRunner*/ {
	/*@Autowired
	RoleRepository repository;*/

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerApplication.class, args);
	}

	/*@Override
	public void run(String... args) throws Exception {
		Role adminRole = Role.builder().role(RoleName.ROLE_ADMIN).build();
		Role userRole = Role.builder().role(RoleName.ROLE_USER).build();
		repository.save(adminRole);
		repository.save(userRole);
	}*/
}
