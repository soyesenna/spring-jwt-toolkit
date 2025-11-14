package com.soyesenna.spring_jwt_toolkit.process.beans;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.exception.JwtProcessingException;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtClaimFieldMetadata;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadata;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadataRegistry;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtTokenSettingsProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

@RequiredArgsConstructor
public class JwtExtractor {

  private final JwtModelMetadataRegistry metadataRegistry;
  private final JwtTokenSettingsProvider tokenSettingsProvider;
  private final ObjectMapper objectMapper;

  public <T> JwtExtractionResult<T> extract(String token, TokenType tokenType,
      Class<T> modelClass) {
    Assert.hasText(token, "token must not be empty");
    Assert.notNull(tokenType, "tokenType must not be null");
    Assert.notNull(modelClass, "modelClass must not be null");

    Claims claims = parseClaims(token, tokenType);
    JwtModelMetadata metadata = this.metadataRegistry.getMetadata(modelClass);
    Object body = metadata.createInstance();

    Field subjectField = metadata.getSubjectField(tokenType);
    if (subjectField != null) {
      Object convertedSubject = convertValue(claims.getSubject(), subjectField.getType());
      ReflectionUtils.setField(subjectField, body, convertedSubject);
    }

    for (JwtClaimFieldMetadata claimMetadata : metadata.getClaimFields(tokenType)) {
      Object value = claims.get(claimMetadata.claimName());
      if (value != null) {
        Object converted = convertValue(value, claimMetadata.field().getType());
        ReflectionUtils.setField(claimMetadata.field(), body, converted);
      }
    }

    return new JwtExtractionResult<>(
        token, tokenType, claims, modelClass.cast(body));
  }

  private Claims parseClaims(String token, TokenType tokenType) {
    try {
      return Jwts.parser()
          .verifyWith(tokenSettingsProvider.getSigningKey(tokenType))
          .build()
          .parseSignedClaims(token)
          .getPayload();
    } catch (JwtException ex) {
      throw new JwtProcessingException(
          "Failed to parse %s token: %s".formatted(tokenType, ex.getMessage()), ex);
    }
  }

  private Object convertValue(Object value, Class<?> targetType) {
    if (value == null) {
      return null;
    }
    if (targetType.isInstance(value)) {
      return value;
    }
    if (targetType == String.class) {
      return value.toString();
    }
    if (targetType.isPrimitive()) {
      targetType = ClassUtils.resolvePrimitiveIfNecessary(targetType);
    }
    if (Number.class.isAssignableFrom(targetType) && value instanceof Number number) {
      return convertNumber(number, targetType);
    }
    if (targetType == Boolean.class && value instanceof Boolean bool) {
      return bool;
    }
    if (Collection.class.isAssignableFrom(targetType) || Map.class.isAssignableFrom(targetType)) {
      return objectMapper.convertValue(value,
          objectMapper.getTypeFactory().constructType(targetType));
    }
    return objectMapper.convertValue(value, targetType);
  }

  private Object convertNumber(Number number, Class<?> targetType) {
    if (targetType == Integer.class) {
      return number.intValue();
    }
    if (targetType == Long.class) {
      return number.longValue();
    }
    if (targetType == Double.class) {
      return number.doubleValue();
    }
    if (targetType == Float.class) {
      return number.floatValue();
    }
    if (targetType == Short.class) {
      return number.shortValue();
    }
    if (targetType == Byte.class) {
      return number.byteValue();
    }
    return number;
  }
}
