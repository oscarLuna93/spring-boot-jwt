package com.oscar.springboot.app.auth.service;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import io.jsonwebtoken.Claims;

public class JWTServiceImpl implements JWTService{

	@Override
	public String create(Authentication auth) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean validate(String token) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Claims getClaims(String token) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getUsername(String token) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String resolve(String token) {
		// TODO Auto-generated method stub
		return null;
	}

}
