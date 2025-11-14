package com.soyesenna.spring_jwt_toolkit.process.internal;

import java.lang.reflect.Field;

/**
 * Describes the mapping between a field declared on a {@link com.soyesenna.spring_jwt_toolkit.annotations.JwtModel}
 * and the corresponding JWT claim name.
 *
 * @param claimName name of the claim in the JWT payload
 * @param field reflective handle used to read/write the value on the model
 */
public record JwtClaimFieldMetadata(
    String claimName,
    Field field
) {

}
