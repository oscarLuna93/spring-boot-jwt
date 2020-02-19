package com.oscar.springboot.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.oscar.springboot.app.models.service.IUploadService;

@SpringBootApplication
public class SpringBootDataJpaApplication implements CommandLineRunner{

	@Autowired
	IUploadService uploadService;
	
	private static final int CONTRASEÑAS_CIFRADAS = 2;
	
	@Autowired
	BCryptPasswordEncoder passwordEncoder;
	
	public static void main(String[] args) {
		SpringApplication.run(SpringBootDataJpaApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		uploadService.deleteAll();
		uploadService.init();
		
		String password = "12345";
		
		for (int i = 0; i < CONTRASEÑAS_CIFRADAS; i++) {
			String bcryptPassword = passwordEncoder.encode(password);
			System.out.println(bcryptPassword);
		}
	}

}
