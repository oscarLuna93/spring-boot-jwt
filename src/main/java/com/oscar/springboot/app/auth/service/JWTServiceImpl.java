package com.oscar.springboot.app.auth.service;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oscar.springboot.app.auth.SimpleGrantedAuthorityMixin;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTServiceImpl implements JWTService {

	private final String PRIVATE_KEY_RSA = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD7Q6lUdrgY3neE\n" + 
			"ha/ZcQFo4ZZbl1Mo7epF311ueIsP3ETOw5NzJV8wDJsPccr4wszLskehHqP7PMhJ\n" + 
			"XvBWKsmokuYy+nK51oEh0XL4MnIFrLPp2zZEko7gDTqN8NLTC2APwgeemBqU+K2B\n" + 
			"/AJirudq2MLqO/qJbyKg40//ZQaoSHg8BP4Lbkx+K6KJpxOQWktm6oRGFWYAGN5B\n" + 
			"heRthskZSO4qx+sp0kEfquRdW9ZApjsh+12dpQuj6MPyOp+yC6ewCIzqHF+XU6kZ\n" + 
			"6cFh3UPMCZjSk3p/dwzmEl6MgzofldtvMdy4Mc9JypsLKwq2BFa7OAfqsOGgkpCq\n" + 
			"VKhy+CjJAgMBAAECggEBAJAzqL6c09MR+i3IO7/jJxf2P8CY/FUFFeq74ndAHy8f\n" + 
			"Dy5K+BihXhvJYERg3kgeJELTMmC5oQrTO29AWVZagBmLFSo0qhsVjE7IUd83tFCl\n" + 
			"aSvRbzezlOPpM626hIQyhxMEHDNcwAS3I3zyELxp/M5JULP1cDfn3EvRqVu9szBo\n" + 
			"I9pr4eSJOXo3mK6XbwN71fKaK+Xv0EBYnb3vySWMryEjBzT9Z4zQi1VuEAP1TIdg\n" + 
			"Kv528JTRWM4Wc/tWDvN2qIh/7FbDSYVSPhTCGY5AQTDHUl1xM4yMiGDNxnLMo1wa\n" + 
			"HUmGnqrKX8WzKSQacQRgMuEjtpDc3+8HFDJoaH5fjbECgYEA/0EOQgSl72hOFnsg\n" + 
			"JTDcSwWlcvu2FNhUXt9cO8DKnUuqaTOFdqjZtGfqxk266j76y2i2ovZvTxS8qWcv\n" + 
			"NTPq1QALxh3/tLrz5371ehfB8/Ezbhv+YX8GTFJlOuMhR+xyBOBW6RfRMBzI7Y1l\n" + 
			"4SKF5ZAPR+cP9Iq9Md3o+IF2SPMCgYEA+/+fAyLin1QYY3ngOCk9acep3bKew7D6\n" + 
			"OeoIuPJIilgufBcb7XNwcvnz+M2SKZXvKC9N8BIqSnYvOHOd7WG/me2mVJGUe/mB\n" + 
			"vNIHpa1plrArxOmUFWVkOOdhL4cqov8FSCUH7TgK9BBfbCfLm3DM8BWGTGJZdEKE\n" + 
			"WlnFRCOn9lMCgYAROA1DLNcYyFuELrgjaiFiOjZIBGzrCRDf+YdaTI4egE01nZEi\n" + 
			"SQ+umNgAmpvCU49Ni3nOkns9xXNYpipMF31+8urYaYunYHk1o53hp5qg3yOOCPtn\n" + 
			"Dk+ZdHF5wHqtRGkIpS2XudCVw0tWoxQ9VLvdmZM+UXsFDxrmM0cVBH67OwKBgEhb\n" + 
			"k8sQv0XEneQiYLF/lfTDshDIczH5pT/v5WVFnHKs81wKPqil1woMn3M3g9qRBMTj\n" + 
			"IFvou1/6I4DwIc7BnISUaogp7RrT/9656Bw4ePMdztORxkWGgYqdVZiSFToMQ/X9\n" + 
			"PBNvXiXKdbvWiW4uq4nchF12d/0cBGj1EeGI43elAoGAQWkwNGYwHP/6ansz4Lpo\n" + 
			"be0c0RUYTiRWKFRBBnKfmzl7OdufLBGANEbPWY1pu/WMgktf6eRr0Is1yUjmUXmE\n" + 
			"c7ecrP//3biX3d2z1P1LLA86sf7irFvF++EDWQTH/0xRb43wGA09eODk5cQRvzin\n" + 
			"CBEBllhxl7ijpE1ZNLhV5BQ=";
	
	private static final long EXPIRATION_DATE = 3600000;
	
	public static final String TOKEN_PREFIX = "Bearer ";
	
	public static final String HEADER_STRING = "Authorization";
	
	@Override
	public String create(Authentication auth) throws IOException {
		String username = ((User) auth.getPrincipal()).getUsername();

		Collection<? extends GrantedAuthority> roles = auth.getAuthorities();

		Claims claims = Jwts.claims();
		claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

		// forma automatica, llave por default
		// SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

		SecretKey secretKey = Keys.hmacShaKeyFor(PRIVATE_KEY_RSA.getBytes());

		String token = Jwts.builder().setClaims(claims).setSubject(username).signWith(secretKey).setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_DATE)).compact();
		
		return token;
	}

	@Override
	public boolean validate(String token) {		
		try {
			getClaims(token);
			return true;
		} catch (JwtException | IllegalArgumentException e) {
			return false;
		}
	}

	@Override
	public Claims getClaims(String token) {
		Claims claims = Jwts.parserBuilder().setSigningKey(PRIVATE_KEY_RSA.getBytes()).build()
				.parseClaimsJws(resolve(token))
				.getBody();
		
		return claims;
	}

	@Override
	public String getUsername(String token) {
		return getClaims(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException {
		Object roles = getClaims(token).get("authorities");
		
		return Arrays.asList(new ObjectMapper()
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
				.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
	}

	@Override
	public String resolve(String token) {
		if (token != null && token.startsWith(TOKEN_PREFIX)) {
			return token.replace(TOKEN_PREFIX, "");
		}
		return null;
	}

}
