package com.soyesenna.spring_jwt_toolkit.process.beans;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.CollectionUtils;

@RequiredArgsConstructor
public class JwtAuthenticator {

  private final JwtExtractor jwtExtractor;

  public <T> JwtAuthenticationToken authenticate(
      String token, TokenType tokenType, Class<T> modelClass
  ) {
    return authenticate(token, tokenType, modelClass, List.of());
  }

  public <T> JwtAuthenticationToken authenticate(
      String token,
      TokenType tokenType,
      Class<T> modelClass,
      Collection<? extends GrantedAuthority> authorities
  ) {
    JwtExtractionResult<T> extraction = this.jwtExtractor.extract(token, tokenType, modelClass);
    Collection<? extends GrantedAuthority> safeAuthorities =
        CollectionUtils.isEmpty(authorities) ? List.of() : List.copyOf(authorities);
    return new JwtAuthenticationToken(
        extraction.tokenType(),
        extraction.token(),
        extraction.claims(),
        extraction.body(),
        safeAuthorities
    );
  }
}
