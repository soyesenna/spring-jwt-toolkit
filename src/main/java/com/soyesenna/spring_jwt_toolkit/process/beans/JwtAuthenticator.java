package com.soyesenna.spring_jwt_toolkit.process.beans;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.CollectionUtils;

/**
 * Helper component that wraps {@link JwtExtractor} and returns {@link JwtAuthenticationToken}
 * instances suitable for Spring Security authentication flows.
 */
public class JwtAuthenticator {

  private final JwtExtractor jwtExtractor;

  /**
   * Creates an authenticator backed by the given extractor.
   *
   * @param jwtExtractor component responsible for parsing JWTs
   */
  public JwtAuthenticator(JwtExtractor jwtExtractor) {
    this.jwtExtractor = jwtExtractor;
  }

  /**
   * Authenticates a JWT using the supplied model class without attaching authorities.
   *
   * @param token compact JWT string
   * @param tokenType token classification
   * @param modelClass target model type used for claim hydration
   * @param <T> model type
   * @return {@link JwtAuthenticationToken} populated with the extracted body
   */
  public <T> JwtAuthenticationToken authenticate(
      String token, TokenType tokenType, Class<T> modelClass
  ) {
    return authenticate(token, tokenType, modelClass, List.of());
  }

  /**
   * Authenticates a JWT and attaches the provided authorities to the resulting token.
   *
   * @param token compact JWT string
   * @param tokenType token classification
   * @param modelClass target model type used for claim hydration
   * @param authorities authorities that should be associated with the authentication
   * @param <T> model type
   * @return {@link JwtAuthenticationToken} ready to be stored in the {@code SecurityContext}
   */
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
