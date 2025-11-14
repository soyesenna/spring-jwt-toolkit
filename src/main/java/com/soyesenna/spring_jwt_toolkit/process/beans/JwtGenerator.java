package com.soyesenna.spring_jwt_toolkit.process.beans;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.exception.JwtConfigurationException;
import com.soyesenna.spring_jwt_toolkit.exception.JwtProcessingException;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtClaimFieldMetadata;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadata;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadataRegistry;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtTokenSettingsProvider;
import io.jsonwebtoken.Jwts;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.springframework.util.ReflectionUtils;

@RequiredArgsConstructor
public class JwtGenerator {

  private final JwtModelMetadataRegistry metadataRegistry;
  private final JwtTokenSettingsProvider tokenSettingsProvider;
  private final ObjectMapper objectMapper;

  public Map<TokenType, JwtToken> generateTokens(Object model) {
    Objects.requireNonNull(model, "model must not be null");
    Map<TokenType, JwtToken> tokens = new EnumMap<>(TokenType.class);
    Stream.of(TokenType.values())
        .forEach(tokenType -> this.generateToken(model, tokenType).ifPresent(
            token -> tokens.put(tokenType, token)));
    return tokens;
  }

  public String generateTokenValue(Object model, TokenType tokenType) {
    return this.generateToken(model, tokenType)
        .map(JwtToken::value)
        .orElseThrow(
            () -> new JwtConfigurationException(
                "No @JwtSubject field configured for token type %s in %s"
                    .formatted(tokenType, model.getClass().getName())
            )
        );
  }

  private Optional<JwtToken> generateToken(Object model, TokenType tokenType) {
    JwtModelMetadata metadata = this.metadataRegistry.getMetadata(model.getClass());
    Field subjectField = metadata.getSubjectField(tokenType);
    if (subjectField == null) {
      return Optional.empty();
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
        claims.put(claimMetadata.claimName(), convertClaimValue(value));
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
    return java.util.Optional.of(new JwtToken(tokenType, tokenValue, issuedAt, expiresAt));
  }

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
}
