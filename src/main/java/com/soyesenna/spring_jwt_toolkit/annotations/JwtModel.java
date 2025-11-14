package com.soyesenna.spring_jwt_toolkit.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Defines a data class that can participate in JWT generation and extraction. Each model represents
 * the canonical structure used for mapping JWT {@code subject} and claim values into strongly typed
 * objects. Classes annotated with {@code @JwtModel} must provide a default constructor so the
 * toolkit can instantiate them reflectively.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface JwtModel {

}
