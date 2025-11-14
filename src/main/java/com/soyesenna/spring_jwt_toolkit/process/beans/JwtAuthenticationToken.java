package com.soyesenna.spring_jwt_toolkit.process.beans;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import io.jsonwebtoken.Claims;
import java.io.Serial;
import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * {@link org.springframework.security.core.Authentication} implementation that encapsulates the
 * output of {@link JwtToolKit}. It stores the raw token, parsed claims, and hydrated principal for
 * downstream security components.
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

  @Serial
  private static final long serialVersionUID = 1L;

  private final TokenType tokenType;
  private final String token;
  private final Claims claims;
  private final Object principal;

  /**
   * Constructs an authenticated token populated with claims and authorities.
   *
   * @param tokenType classification of the processed token
   * @param token raw token value
   * @param claims parsed JWT claims
   * @param principal hydrated model instance derived from the token
   * @param authorities authorities to associate with the token
   */
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

  /**
   * @return the classification of the JWT used to create this authentication
   */
  public TokenType getTokenType() {
    return tokenType;
  }

  /**
   * @return the parsed {@link Claims} contained in the JWT
   */
  public Claims getClaims() {
    return claims;
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
