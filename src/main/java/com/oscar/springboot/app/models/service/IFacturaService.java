package com.oscar.springboot.app.models.service;

import com.oscar.springboot.app.models.entity.Factura;

public interface IFacturaService {
	
	public void saveFactura(Factura factura);
	public Factura findFacturaById(Long id);
	public void deleteFactura(Long id);
	public Factura fetchFacturaByIdWithClienteWithItemFacturaWithProducto(Long id);
}
