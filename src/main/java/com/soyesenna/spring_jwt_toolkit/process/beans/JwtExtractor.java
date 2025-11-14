package com.soyesenna.spring_jwt_toolkit.process.beans;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.exception.JwtProcessingException;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtClaimFieldMetadata;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadata;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadataRegistry;
import com.soyesenna.spring_jwt_toolkit.process.internal.JpaEntityProvider;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtTokenSettingsProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

@RequiredArgsConstructor
public class JwtExtractor {

  private final JwtModelMetadataRegistry metadataRegistry;
  private final JwtTokenSettingsProvider tokenSettingsProvider;
  private final ObjectMapper objectMapper;
  private final boolean useJpa;
  @Nullable
  private final JpaEntityProvider jpaEntityProvider;

  public <T> JwtExtractionResult<T> extract(String token, TokenType tokenType,
      Class<T> modelClass) {
    Assert.hasText(token, "token must not be empty");
    Assert.notNull(tokenType, "tokenType must not be null");
    Assert.notNull(modelClass, "modelClass must not be null");

    Claims claims = this.parseClaims(token, tokenType);
    JwtModelMetadata metadata = this.metadataRegistry.getMetadata(modelClass);
    Object body = metadata.createInstance();

    Field subjectField = metadata.getSubjectField(tokenType);
    if (subjectField != null) {
      Object convertedSubject = this.convertValue(claims.getSubject(), subjectField.getType());
      ReflectionUtils.setField(subjectField, body, convertedSubject);
    }

    for (JwtClaimFieldMetadata claimMetadata : metadata.getClaimFields(tokenType)) {
      Object value = claims.get(claimMetadata.claimName());
      if (value != null) {
        Object converted = this.convertValue(value, claimMetadata.field().getType());
        ReflectionUtils.setField(claimMetadata.field(), body, converted);
      }
    }

    Object resolvedBody = this.resolveBody(modelClass, metadata, body);
    return new JwtExtractionResult<>(
        token, tokenType, claims, modelClass.cast(resolvedBody)
    );
  }

  private Claims parseClaims(String token, TokenType tokenType) {
    try {
      return Jwts.parser()
          .verifyWith(this.tokenSettingsProvider.getSigningKey(tokenType))
          .build()
          .parseSignedClaims(token)
          .getPayload();
    } catch (JwtException ex) {
      throw new JwtProcessingException(
          "Failed to parse %s token: %s".formatted(tokenType, ex.getMessage()), ex
      );
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
      return this.convertNumber(number, targetType);
    }
    if (targetType == Boolean.class && value instanceof Boolean bool) {
      return bool;
    }
    if (Collection.class.isAssignableFrom(targetType) || Map.class.isAssignableFrom(targetType)) {
      return this.objectMapper.convertValue(value,
          this.objectMapper.getTypeFactory().constructType(targetType));
    }
    return this.objectMapper.convertValue(value, targetType);
  }

  private Object resolveBody(
      Class<?> modelClass, JwtModelMetadata metadata, Object candidate
  ) {
    if (!this.useJpa || this.jpaEntityProvider == null) {
      return candidate;
    }
    Field idField = metadata.getJpaIdField();
    if (idField == null) {
      return candidate;
    }
    Object idValue = ReflectionUtils.getField(idField, candidate);
    if (idValue == null) {
      return candidate;
    }
    Object entity = jpaEntityProvider.findEntity(modelClass, idValue).orElse(null);
    if (modelClass.isInstance(entity)) {
      return entity;
    }
    return candidate;
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
