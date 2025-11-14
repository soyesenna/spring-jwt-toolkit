package com.soyesenna.spring_jwt_toolkit.process.beans;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import io.jsonwebtoken.Claims;
import java.io.Serial;
import java.util.Collection;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

  @Serial
  private static final long serialVersionUID = 1L;

  @Getter
  private final TokenType tokenType;

  private final String token;

  @Getter
  private final Claims claims;

  private final Object principal;

  public JwtAuthenticationToken(
      TokenType tokenType,
      String token,
      Claims claims,
      Object principal,
      Collection<? extends GrantedAuthority> authorities
  ) {
    super(authorities);
    this.tokenType = tokenType;
    this.token = token;
    this.claims = claims;
    this.principal = principal;
    super.setAuthenticated(true);
  }

  @Override
  public Object getCredentials() {
    return token;
  }

  @Override
  public Object getPrincipal() {
    return principal;
  }
}
