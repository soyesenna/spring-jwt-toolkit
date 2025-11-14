package com.soyesenna.spring_jwt_toolkit.process.beans;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import java.time.Instant;

/**
 * Immutable description of a generated JWT, including its raw value as well as issued-at and
 * expiration timestamps. Returning this record from generator APIs allows callers to inspect timing
 * metadata without parsing the token again.
 *
 * @param tokenType type of token that was generated
 * @param value compact serialized token string
 * @param issuedAt issuance time captured when the token was minted
 * @param expiresAt instant at which the token becomes invalid
 */
public record JwtToken(
    TokenType tokenType,
    String value,
    Instant issuedAt,
    Instant expiresAt
) {

}
