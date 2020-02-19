package com.oscar.springboot.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.oscar.springboot.app.models.entity.Usuario;

public interface IUsuarioDAO extends CrudRepository<Usuario, Long>{
	
	public Usuario findByUsername(String username);
}
