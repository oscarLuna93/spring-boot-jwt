package com.oscar.springboot.app.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class SimpleGrantedAuthorityMixin {
	
	//constructor por defecto del json
	@JsonCreator
	public SimpleGrantedAuthorityMixin(@JsonProperty("authority") String role) {}
}
