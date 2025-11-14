package com.soyesenna.spring_jwt_toolkit.process.beans;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import io.jsonwebtoken.Claims;

/**
 * Container returned by {@link JwtExtractor} summarizing the outcome of JWT parsing. In addition to
 * the hydrated model, callers receive the raw token value and the parsed {@link Claims} to inspect
 * issuer-specific metadata as needed.
 *
 * @param token raw compact JWT string
 * @param tokenType classification of the token that was processed
 * @param claims underlying claims parsed from the JWT payload
 * @param body fully populated model instance requested by the caller
 * @param <T> model type
 */
public record JwtExtractionResult<T>(
    String token,
    TokenType tokenType,
    Claims claims,
    T body
) {

}
