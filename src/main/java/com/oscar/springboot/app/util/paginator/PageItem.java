package com.oscar.springboot.app.util.paginator;

public class PageItem {
	private int numero;
	private boolean actual;
	
	public PageItem(int numero, boolean esActual) {
		super();
		this.numero = numero;
		this.actual = esActual;
	}

	public int getNumero() {
		return numero;
	}

	public boolean isActual() {
		return actual;
	}

}
