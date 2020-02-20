package com.oscar.springboot.app.auth.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oscar.springboot.app.auth.SimpleGrantedAuthoritiesMixin;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private final String PRIVATE_KEY_RSA = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD7Q6lUdrgY3neE\n"
			+ "ha/ZcQFo4ZZbl1Mo7epF311ueIsP3ETOw5NzJV8wDJsPccr4wszLskehHqP7PMhJ\n"
			+ "XvBWKsmokuYy+nK51oEh0XL4MnIFrLPp2zZEko7gDTqN8NLTC2APwgeemBqU+K2B\n"
			+ "/AJirudq2MLqO/qJbyKg40//ZQaoSHg8BP4Lbkx+K6KJpxOQWktm6oRGFWYAGN5B\n"
			+ "heRthskZSO4qx+sp0kEfquRdW9ZApjsh+12dpQuj6MPyOp+yC6ewCIzqHF+XU6kZ\n"
			+ "6cFh3UPMCZjSk3p/dwzmEl6MgzofldtvMdy4Mc9JypsLKwq2BFa7OAfqsOGgkpCq\n"
			+ "VKhy+CjJAgMBAAECggEBAJAzqL6c09MR+i3IO7/jJxf2P8CY/FUFFeq74ndAHy8f\n"
			+ "Dy5K+BihXhvJYERg3kgeJELTMmC5oQrTO29AWVZagBmLFSo0qhsVjE7IUd83tFCl\n"
			+ "aSvRbzezlOPpM626hIQyhxMEHDNcwAS3I3zyELxp/M5JULP1cDfn3EvRqVu9szBo\n"
			+ "I9pr4eSJOXo3mK6XbwN71fKaK+Xv0EBYnb3vySWMryEjBzT9Z4zQi1VuEAP1TIdg\n"
			+ "Kv528JTRWM4Wc/tWDvN2qIh/7FbDSYVSPhTCGY5AQTDHUl1xM4yMiGDNxnLMo1wa\n"
			+ "HUmGnqrKX8WzKSQacQRgMuEjtpDc3+8HFDJoaH5fjbECgYEA/0EOQgSl72hOFnsg\n"
			+ "JTDcSwWlcvu2FNhUXt9cO8DKnUuqaTOFdqjZtGfqxk266j76y2i2ovZvTxS8qWcv\n"
			+ "NTPq1QALxh3/tLrz5371ehfB8/Ezbhv+YX8GTFJlOuMhR+xyBOBW6RfRMBzI7Y1l\n"
			+ "4SKF5ZAPR+cP9Iq9Md3o+IF2SPMCgYEA+/+fAyLin1QYY3ngOCk9acep3bKew7D6\n"
			+ "OeoIuPJIilgufBcb7XNwcvnz+M2SKZXvKC9N8BIqSnYvOHOd7WG/me2mVJGUe/mB\n"
			+ "vNIHpa1plrArxOmUFWVkOOdhL4cqov8FSCUH7TgK9BBfbCfLm3DM8BWGTGJZdEKE\n"
			+ "WlnFRCOn9lMCgYAROA1DLNcYyFuELrgjaiFiOjZIBGzrCRDf+YdaTI4egE01nZEi\n"
			+ "SQ+umNgAmpvCU49Ni3nOkns9xXNYpipMF31+8urYaYunYHk1o53hp5qg3yOOCPtn\n"
			+ "Dk+ZdHF5wHqtRGkIpS2XudCVw0tWoxQ9VLvdmZM+UXsFDxrmM0cVBH67OwKBgEhb\n"
			+ "k8sQv0XEneQiYLF/lfTDshDIczH5pT/v5WVFnHKs81wKPqil1woMn3M3g9qRBMTj\n"
			+ "IFvou1/6I4DwIc7BnISUaogp7RrT/9656Bw4ePMdztORxkWGgYqdVZiSFToMQ/X9\n"
			+ "PBNvXiXKdbvWiW4uq4nchF12d/0cBGj1EeGI43elAoGAQWkwNGYwHP/6ansz4Lpo\n"
			+ "be0c0RUYTiRWKFRBBnKfmzl7OdufLBGANEbPWY1pu/WMgktf6eRr0Is1yUjmUXmE\n"
			+ "c7ecrP//3biX3d2z1P1LLA86sf7irFvF++EDWQTH/0xRb43wGA09eODk5cQRvzin\n" + "CBEBllhxl7ijpE1ZNLhV5BQ=";

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String header = request.getHeader("Authorization");

		if (!requiresAuthentication(header)) {
			chain.doFilter(request, response);
			return;
		}

		boolean tokenIsValid;
		Claims token = null;

		try {
			token = Jwts.parserBuilder().setSigningKey(PRIVATE_KEY_RSA.getBytes()).build()
					.parseClaimsJws(header.replace("Bearer", "")).getBody();
			tokenIsValid = true;
		} catch (JwtException | IllegalArgumentException e) {
			tokenIsValid = false;
		}

		UsernamePasswordAuthenticationToken authentication = null;
		if (tokenIsValid) {
			String username = token.getSubject();
			Object roles = token.get("authorities");

			Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
					.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthoritiesMixin.class)
					.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));

			authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
		}
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
	}

	protected boolean requiresAuthentication(String header) {
		if (header == null || !header.startsWith("Bearer ")) {
			return false;
		}

		return true;
	}

}
