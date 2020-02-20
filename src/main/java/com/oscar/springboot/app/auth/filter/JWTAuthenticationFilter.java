package com.oscar.springboot.app.auth.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	private AuthenticationManager authenticationManager;
	
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
	
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		String username = obtainUsername(request);
		String password = obtainPassword(request);

		if (username == null) {
			username = "";
		}

		if (password == null) {
			password = "";
		}
		
		if (username != null && password != null) {
			logger.info("Username desde request parameter (form-data): " + username);
			logger.info("Password desde request parameter (form-data): " + password);
		}

		username = username.trim();

		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
		
		return authenticationManager.authenticate(authToken);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		String username = ( (User) authResult.getPrincipal()).getUsername();
		
		//forma automatica, llave por default
		//SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);
		
		SecretKey secretKey = Keys.hmacShaKeyFor(PRIVATE_KEY_RSA.getBytes());
		
		String token = Jwts.builder()
				.setSubject(username)
				.signWith(secretKey)
				.compact();
		
		response.addHeader("Authorization", "Bearer ".concat(token));
		
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("token", token);
		body.put("user", (User) authResult.getPrincipal());
		body.put("mensaje", String.format("Hola %s has iniciado sesion con exito", username));
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(200);
		response.setContentType("application/json");
	}
}