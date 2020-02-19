package com.oscar.springboot.app.models.service;

import java.util.List;

import com.oscar.springboot.app.models.entity.Producto;

public interface IProductoService {
	public List<Producto> findByNombre(String term);
	public Producto findProductoById(Long id);
}
