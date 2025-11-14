package com.soyesenna.spring_jwt_toolkit.annotations;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a field on a {@link JwtModel}-annotated class as a claim that should be written to and read
 * from JWT payloads. The toolkit inspects these annotations during metadata discovery and maps the
 * configured claim name to the matching field when generating or extracting tokens.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface JwtClaim {

  /**
   * @return the claim name that should be used inside the JWT payload
   */
  String name();

  /**
   * @return the token types for which the claim should be included; defaults to access tokens only
   */
  TokenType[] tokenTypes() default {TokenType.ACCESS};
}
