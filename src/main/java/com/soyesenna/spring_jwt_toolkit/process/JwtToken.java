package com.soyesenna.spring_jwt_toolkit.process;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import java.time.Instant;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

public record JwtToken(
    TokenType tokenType,
    String value,
    Instant issuedAt,
    Instant expiresAt
) {

}