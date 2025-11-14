package com.soyesenna.spring_jwt_toolkit.annotations;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface JwtSubject {

  TokenType[] tokenTypes() default {TokenType.ACCESS, TokenType.REFRESH};
}
