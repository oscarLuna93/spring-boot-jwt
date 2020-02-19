package com.oscar.springboot.app.models.service;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.oscar.springboot.app.models.dao.IUsuarioDAO;
import com.oscar.springboot.app.models.entity.Role;
import com.oscar.springboot.app.models.entity.Usuario;

@Service("jpaUserDetailsService")
public class JpaUserDetailsService implements UserDetailsService{

	@Autowired
	private IUsuarioDAO usuarioDao;
	
	private Logger logger = LoggerFactory.getLogger(JpaUserDetailsService.class);
	
	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Usuario usuario = usuarioDao.findByUsername(username);
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		
		if (usuario == null) {
			logger.error("Error login: no existe el usuario " + username);
			throw new UsernameNotFoundException(username + " no existe");
		}
		
		for(Role rol: usuario.getRoles()) {
			authorities.add(new SimpleGrantedAuthority(rol.getAuthority()));
		}
		
		if (authorities.isEmpty()) {
			logger.error("Error Login: el usuario " + username + " no tiene roles asignados");
			throw new UsernameNotFoundException(username + " no tiene roles asignados");
		}
			
		return new User(usuario.getUsername(), usuario.getPassword(), usuario.getEnabled(), true, true, true, authorities);
	}
	
}