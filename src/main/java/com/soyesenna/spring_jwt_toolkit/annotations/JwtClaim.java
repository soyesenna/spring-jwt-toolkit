package com.soyesenna.spring_jwt_toolkit.annotations;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface JwtClaim {
  String name();
  TokenType[] tokenTypes() default { TokenType.ACCESS };
}
