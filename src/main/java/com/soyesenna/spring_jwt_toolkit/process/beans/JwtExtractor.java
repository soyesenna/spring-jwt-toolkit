package com.soyesenna.spring_jwt_toolkit.process.beans;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.exception.JwtProcessingException;
import com.soyesenna.spring_jwt_toolkit.process.internal.JpaEntityProvider;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtClaimFieldMetadata;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadata;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadataRegistry;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtTokenSettingsProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Map;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

/**
 * Parses JWT strings, verifies their signatures, and hydrates {@link JwtExtractionResult} instances
 * populated with strongly typed model objects. When configured, it can also rehydrate entities using
 * a JPA {@code EntityManager}.
 */
public class JwtExtractor {

  private final JwtModelMetadataRegistry metadataRegistry;
  private final JwtTokenSettingsProvider tokenSettingsProvider;
  private final ObjectMapper objectMapper;
  private final boolean useJpa;
  @Nullable
  private final JpaEntityProvider jpaEntityProvider;

  /**
   * Creates an extractor with the dependencies required to parse and verify JWTs.
   *
   * @param metadataRegistry cache for model metadata
   * @param tokenSettingsProvider provides signing keys
   * @param objectMapper mapper used for converting complex claim bodies
   * @param useJpa whether JPA entity lookup should be attempted
   * @param jpaEntityProvider optional provider that wraps an {@code EntityManager}
   */
  public JwtExtractor(
      JwtModelMetadataRegistry metadataRegistry,
      JwtTokenSettingsProvider tokenSettingsProvider,
      ObjectMapper objectMapper,
      boolean useJpa,
      @Nullable JpaEntityProvider jpaEntityProvider
  ) {
    this.metadataRegistry = metadataRegistry;
    this.tokenSettingsProvider = tokenSettingsProvider;
    this.objectMapper = objectMapper;
    this.useJpa = useJpa;
    this.jpaEntityProvider = jpaEntityProvider;
  }

  /**
   * Verifies the token signature, maps the payload into the requested model, and optionally loads
   * the entity via JPA.
   *
   * @param token raw JWT value
   * @param tokenType classification of the token to select signing keys
   * @param modelClass desired model type
   * @param <T> model type parameter
   * @return populated extraction result containing the token, claims, and model
   */
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

    Object resolvedBody = resolveBody(modelClass, metadata, body);
    return new JwtExtractionResult<>(
        token, tokenType, claims, modelClass.cast(resolvedBody));
  }

  /**
   * Parses and verifies a JWT prior to claim extraction.
   *
   * @param token raw token value
   * @param tokenType token classification used to select the signing key
   * @return parsed claims
   */
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

  /**
   * Converts arbitrary claim values into the requested target type.
   *
   * @param value value sourced from the JWT claims map
   * @param targetType field type declared on the model
   * @return converted value compatible with the field
   */
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

  /**
   * Resolves the final model instance. When JPA integration is enabled the method attempts to load
   * an entity by ID; otherwise the reflectively populated object is returned.
   *
   * @param modelClass model type requested by the caller
   * @param metadata metadata describing the model
   * @param candidate instance created via reflection prior to JPA lookup
   * @return entity managed by JPA or the original candidate
   */
  private Object resolveBody(
      Class<?> modelClass, JwtModelMetadata metadata, Object candidate) {
    if (!useJpa || jpaEntityProvider == null) {
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
    if (entity != null && modelClass.isInstance(entity)) {
      return entity;
    }
    return candidate;
  }

  /**
   * Performs numeric conversions while preserving the requested boxed type.
   *
   * @param number numeric value extracted from the token
   * @param targetType desired boxed type
   * @return converted number
   */
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
