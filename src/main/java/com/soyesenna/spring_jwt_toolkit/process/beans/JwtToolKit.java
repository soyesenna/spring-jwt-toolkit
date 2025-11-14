package com.soyesenna.spring_jwt_toolkit.process.beans;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.exception.JwtConfigurationException;
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
import java.time.Instant;
import java.util.Collection;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

/**
 * Central toolkit that covers token generation and extraction. It merges the functionality
 * previously provided by {@code JwtGenerator} and {@code JwtExtractor} into a single entry point
 * while retaining the detailed documentation of each responsibility.
 */
public class JwtToolKit {

  private final JwtModelMetadataRegistry metadataRegistry;
  private final JwtTokenSettingsProvider tokenSettingsProvider;
  private final ObjectMapper objectMapper;
  private final boolean useJpa;
  @Nullable
  private final JpaEntityProvider jpaEntityProvider;

  /**
   * Creates a new toolkit with the dependencies required to inspect metadata, sign tokens, and
   * hydrate models.
   *
   * @param metadataRegistry cache for model introspection results
   * @param tokenSettingsProvider provides signing keys and validity durations
   * @param objectMapper mapper used to convert arbitrary claim values into JSON-compatible shapes
   * @param useJpa whether JPA entity lookups should be attempted after extraction
   * @param jpaEntityProvider optional adapter around an {@code EntityManager}
   */
  public JwtToolKit(
      JwtModelMetadataRegistry metadataRegistry,
      JwtTokenSettingsProvider tokenSettingsProvider,
      ObjectMapper objectMapper,
      boolean useJpa,
      @Nullable JpaEntityProvider jpaEntityProvider
  ) {
    this.metadataRegistry = Objects.requireNonNull(metadataRegistry, "metadataRegistry must not be null");
    this.tokenSettingsProvider =
        Objects.requireNonNull(tokenSettingsProvider, "tokenSettingsProvider must not be null");
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    this.useJpa = useJpa;
    this.jpaEntityProvider = jpaEntityProvider;
  }

  /// ========== GENERATE LOGIC ========== ///
  /**
   * Generates a token for every {@link TokenType}, skipping entries that lack a configured subject
   * field.
   *
   * @param model model instance annotated with {@code @JwtModel}
   * @return immutable map of generated tokens keyed by {@link TokenType}
   */
  public Map<TokenType, JwtToken> generateTokens(Object model) {
    Objects.requireNonNull(model, "model must not be null");
    Map<TokenType, JwtToken> tokens = new EnumMap<>(TokenType.class);
    Stream.of(TokenType.values())
        .forEach(tokenType -> tokens.put(tokenType, this.generateToken(model, tokenType)));
    return Map.copyOf(tokens);
  }

  /**
   * Convenience method that generates an access token only. Throws if the model does not expose a
   * {@code @JwtSubject} field for {@link TokenType#ACCESS}.
   *
   * @param model annotated model
   * @return generated access token
   */
  public JwtToken generateAccessToken(Object model) {
    Objects.requireNonNull(model, "model must not be null");
    return this.generateToken(model, TokenType.ACCESS);
  }

  /**
   * Convenience method that generates a refresh token only. Throws if the model lacks a refresh
   * {@code @JwtSubject}.
   *
   * @param model annotated model
   * @return generated refresh token
   */
  public JwtToken generateRefreshToken(Object model) {
    Objects.requireNonNull(model, "model must not be null");
    return this.generateToken(model, TokenType.REFRESH);
  }

  /**
   * Generates a single token value for the supplied type, throwing an exception if the model does
   * not expose a subject field for that type.
   *
   * @param model annotated model instance
   * @param tokenType desired token classification
   * @return signed JWT value
   */
  public String generateTokenValue(Object model, TokenType tokenType) {
    return this.generateToken(model, tokenType).value();
  }

  /**
   * Generates a token for the requested type if the model contains a compatible subject field.
   */
  private JwtToken generateToken(Object model, TokenType tokenType) {
    JwtModelMetadata metadata = this.metadataRegistry.getMetadata(model.getClass());
    Field subjectField = metadata.getSubjectField(tokenType);
    if (subjectField == null) {
      throw new JwtConfigurationException(
          "No @JwtSubject field configured for token type %s in %s"
              .formatted(tokenType, model.getClass().getName())
      );
    }

    Object subjectValue = ReflectionUtils.getField(subjectField, model);
    if (subjectValue == null) {
      throw new JwtProcessingException(
          "Subject field %s in %s must not be null when generating %s token"
              .formatted(subjectField.getName(), model.getClass().getName(), tokenType)
      );
    }

    String subject = String.valueOf(subjectValue);
    Map<String, Object> claims = new HashMap<>();
    for (JwtClaimFieldMetadata claimMetadata : metadata.getClaimFields(tokenType)) {
      Object value = ReflectionUtils.getField(claimMetadata.field(), model);
      if (value != null) {
        claims.put(claimMetadata.claimName(), this.convertClaimValue(value));
      }
    }

    Instant issuedAt = Instant.now();
    Instant expiresAt = issuedAt.plus(this.tokenSettingsProvider.getValidity(tokenType));
    var builder =
        Jwts.builder()
            .subject(subject)
            .issuedAt(java.util.Date.from(issuedAt))
            .expiration(java.util.Date.from(expiresAt));

    claims.forEach(builder::claim);

    String tokenValue =
        builder.signWith(this.tokenSettingsProvider.getSigningKey(tokenType)).compact();
    return new JwtToken(tokenType, tokenValue, issuedAt, expiresAt);
  }

  /**
   * Converts arbitrary claim values into JSON-compatible payloads while preserving simple values.
   *
   * @param value value read from the model field
   * @return normalized representation supported by the JWT library
   */
  private Object convertClaimValue(Object value) {
    if (value == null) {
      return null;
    }

    if (value instanceof String
        || value instanceof Number
        || value instanceof Boolean
        || value instanceof Map<?, ?>
        || value instanceof Iterable<?>) {
      return value;
    }

    return this.objectMapper.convertValue(value, Object.class);
  }

  /// ========== EXTRACT ========== ///
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
          .verifyWith(this.tokenSettingsProvider.getSigningKey(tokenType))
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
    Object entity = this.jpaEntityProvider.findEntity(modelClass, idValue).orElse(null);
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
