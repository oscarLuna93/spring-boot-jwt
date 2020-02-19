package com.oscar.springboot.app.controllers;

import java.util.List;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.oscar.springboot.app.models.entity.Cliente;
import com.oscar.springboot.app.models.entity.Factura;
import com.oscar.springboot.app.models.entity.ItemFactura;
import com.oscar.springboot.app.models.entity.Producto;
import com.oscar.springboot.app.models.service.IClienteService;
import com.oscar.springboot.app.models.service.IFacturaService;
import com.oscar.springboot.app.models.service.IProductoService;

@Controller
@RequestMapping("/factura")
@SessionAttributes("factura")
public class FacturaController {

	private final Logger log = LoggerFactory.getLogger(this.getClass());
	@Autowired
	private IClienteService clienteService;
	
	@Autowired
	private IProductoService productoService;
	
	@Autowired
	private IFacturaService facturaService;
	
	@GetMapping("/form/{clienteId}")
	public String crear(@PathVariable(value = "clienteId") Long clienteId
			, Model model, RedirectAttributes flash) {
		Cliente cliente = clienteService.findOne(clienteId);
		
		if (cliente == null) {
			flash.addFlashAttribute("error", "El cliente no existe");
			return "redirect:/listar";
		}
		
		Factura factura = new Factura();
		factura.setCliente(cliente);
		
		model.addAttribute("factura", factura);
		model.addAttribute("titulo", "Crear Factura");
		
		return "factura/form";
	}
	
	@GetMapping(value = "/cargar-productos/{term}", produces = {"application/json"})
	public @ResponseBody List<Producto> cargarProductos(@PathVariable String term) {
		return productoService.findByNombre(term);
	}
	
	@PostMapping("/form")
	public String guardar(@Valid Factura factura,
			BindingResult result,
			Model model,
			@RequestParam(name = "item_id[]", required = false) Long[] itemId,
			@RequestParam(name = "cantidad[]", required = false) Integer[] cantidad,
			RedirectAttributes flash, SessionStatus status) {
		
		if (result.hasErrors()) {
			model.addAttribute("titulo", "Crear Factura");
			return "factura/form";
		}
		
		if (itemId == null || itemId.length == 0) {
			model.addAttribute("titulo", "Crear Factura");
			model.addAttribute("error", "Error: La factura NO puede no tener lineas");
			return "factura/form";
		}
		
		for (int i = 0; i < itemId.length; i++) {
			Producto producto = productoService.findProductoById(itemId[i]);
			
			ItemFactura linea = new ItemFactura();
			linea.setCantidad(cantidad[i]);
			linea.setProducto(producto);
			factura.addItemFactura(linea);
			
			log.info("ID: " + itemId[i].toString() + ", cantidad " + cantidad[i].toString());
		}
		
		facturaService.saveFactura(factura);
		status.setComplete();
		flash.addAttribute("success", "Factura creada con exito");
		
		return "redirect:/ver/".concat(factura.getCliente().getId().toString());
	}
	
	@GetMapping("/ver/{id}")
	public String ver(@PathVariable(value = "id") Long id,
			Model model, RedirectAttributes flash) {
		
		Factura factura = facturaService.fetchFacturaByIdWithClienteWithItemFacturaWithProducto(id);
		
		if (factura == null) {
			flash.addAttribute("error", "La factura no existe");
			return "redirect:/listar";
		}
		
		model.addAttribute("factura", factura);
		model.addAttribute("titulo", "Factura: ".concat(factura.getDescripcion()));
		
		return "factura/ver";
	}
	
	@GetMapping("/eliminar/{id}")
	public String eliminar(@PathVariable(value = "id") Long id,
			RedirectAttributes flash) {
		Factura factura = facturaService.findFacturaById(id);
		
		if (factura != null) {
			facturaService.deleteFactura(id);
			flash.addAttribute("success", "factura eliminada con exito");
			return "redirect:/ver/".concat(factura.getCliente().getId().toString());
		}
		flash.addFlashAttribute("error", "La factura no existe");
		return "redirect:/listar";
	}
}