package com.soyesenna.spring_jwt_toolkit.annotations;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Identifies the field within a {@link JwtModel} that should be mapped to the JWT {@code sub}
 * (subject) value. The annotation is {@link Inherited} so subclasses automatically retain the same
 * semantic meaning for subject fields declared in a superclass.
 */
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface JwtSubject {

  /**
   * @return the collection of token types that should use this field for their {@code sub} claim
   */
  TokenType[] tokenTypes() default {TokenType.ACCESS, TokenType.REFRESH};
}
