package com.soyesenna.spring_jwt_toolkit.process.internal;

import com.soyesenna.spring_jwt_toolkit.configuration.JwtProperties;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.exception.JwtConfigurationException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.EnumMap;
import java.util.Map;
import javax.crypto.SecretKey;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Validates and exposes signing settings derived from {@link JwtProperties}. The provider lazily
 * supplies signing keys and validity durations for each {@link TokenType}.
 */
public class JwtTokenSettingsProvider {

  private final Map<TokenType, JwtTokenSettings> settings = new EnumMap<>(TokenType.class);

  /**
   * Creates a provider initialized from the supplied properties.
   *
   * @param properties strongly typed configuration backing JWT behaviour
   */
  public JwtTokenSettingsProvider(JwtProperties properties) {
    Assert.notNull(properties, "properties must not be null");
    properties.asMap().forEach(this::registerSettings);
  }

  /**
   * Validates and caches the token settings for an individual {@link TokenType}.
   *
   * @param tokenType token classification
   * @param tokenSettings raw configuration slice that should be validated and stored
   */
  private void registerSettings(TokenType tokenType, JwtProperties.TokenSettings tokenSettings) {
    if (!StringUtils.hasText(tokenSettings.getKey())) {
      throw new JwtConfigurationException(
          "jwt.%s.key must not be empty".formatted(tokenType.name().toLowerCase()));
    }

    Duration validity = tokenSettings.getValidity();
    if (validity == null || validity.isZero() || validity.isNegative()) {
      throw new JwtConfigurationException(
          "jwt.%s.validity must be a positive duration".formatted(tokenType.name().toLowerCase())
      );
    }

    byte[] keyBytes = this.decodeKey(tokenSettings.getKey());
    SecretKey secretKey = Keys.hmacShaKeyFor(keyBytes);
    settings.put(tokenType, new JwtTokenSettings(secretKey, validity));
  }

  /**
   * Decodes keys that might be Base64-encoded while falling back to raw UTF-8 bytes for plain text.
   *
   * @param value configured key
   * @return decoded key bytes
   */
  private byte[] decodeKey(String value) {
    try {
      return Decoders.BASE64.decode(value);
    } catch (RuntimeException ex) {
      return value.getBytes(StandardCharsets.UTF_8);
    }
  }

  /**
   * @return signing key for the requested token type
   */
  public SecretKey getSigningKey(TokenType tokenType) {
    return this.getSettings(tokenType).secretKey();
  }

  /**
   * @return configured validity for the requested token type
   */
  public Duration getValidity(TokenType tokenType) {
    return this.getSettings(tokenType).validity();
  }

  /**
   * Locates cached settings or raises a descriptive configuration error.
   *
   * @param tokenType token classification
   * @return immutable pair describing signing key and validity
   */
  private JwtTokenSettings getSettings(TokenType tokenType) {
    JwtTokenSettings tokenSettings = settings.get(tokenType);
    if (tokenSettings == null) {
      throw new JwtConfigurationException(
          "No jwt configuration found for token type %s".formatted(tokenType)
      );
    }
    return tokenSettings;
  }

  /**
   * Value object storing the signing key and validity for a token type.
   */
  private record JwtTokenSettings(SecretKey secretKey, Duration validity) {}
}
