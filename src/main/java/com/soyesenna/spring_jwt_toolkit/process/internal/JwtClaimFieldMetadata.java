package com.soyesenna.spring_jwt_toolkit.process.internal;

import java.lang.reflect.Field;

public record JwtClaimFieldMetadata(
    String claimName,
    Field field
) {

}
