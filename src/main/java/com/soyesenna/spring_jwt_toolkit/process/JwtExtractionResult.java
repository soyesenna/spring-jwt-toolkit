package com.soyesenna.spring_jwt_toolkit.process;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import io.jsonwebtoken.Claims;

public record JwtExtractionResult<T>(
    String token,
    TokenType tokenType,
    Claims claims,
    T body
) {

}
