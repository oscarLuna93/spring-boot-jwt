package com.oscar.springboot.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.oscar.springboot.app.models.dao.IProductoDao;
import com.oscar.springboot.app.models.entity.Producto;

@Service
public class ProductoServiceImpl implements IProductoService{

	@Autowired
	IProductoDao productoDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<Producto> findByNombre(String term) {
		return productoDao.findByNombreLikeIgnoreCase("%" + term + "%");
	}

	@Override
	@Transactional(readOnly = true)
	public Producto findProductoById(Long id) {
		return productoDao.findById(id).orElse(null);
	}
	
}
