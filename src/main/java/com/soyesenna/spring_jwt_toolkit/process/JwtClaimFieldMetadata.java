package com.soyesenna.spring_jwt_toolkit.process;

import java.lang.reflect.Field;

record JwtClaimFieldMetadata(
    String claimName,
    Field field
) {

}
