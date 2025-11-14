package com.soyesenna.spring_jwt_toolkit.process;

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

public class JwtTokenSettingsProvider {

  private final Map<TokenType, JwtTokenSettings> settings = new EnumMap<>(TokenType.class);

  public JwtTokenSettingsProvider(JwtProperties properties) {
    Assert.notNull(properties, "properties must not be null");
    properties.asMap().forEach(this::registerSettings);
  }

  private void registerSettings(TokenType tokenType, JwtProperties.TokenSettings tokenSettings) {
    if (!StringUtils.hasText(tokenSettings.getKey())) {
      throw new JwtConfigurationException(
          "jwt.%s.key must not be empty".formatted(tokenType.name().toLowerCase()));
    }

    Duration validity = tokenSettings.getValidity();
    if (validity == null || validity.isZero() || validity.isNegative()) {
      throw new JwtConfigurationException(
          "jwt.%s.validity must be a positive duration".formatted(tokenType.name().toLowerCase()));
    }

    byte[] keyBytes = decodeKey(tokenSettings.getKey());
    SecretKey secretKey = Keys.hmacShaKeyFor(keyBytes);
    settings.put(tokenType, new JwtTokenSettings(secretKey, validity));
  }

  private byte[] decodeKey(String value) {
    try {
      return Decoders.BASE64.decode(value);
    } catch (IllegalArgumentException ex) {
      return value.getBytes(StandardCharsets.UTF_8);
    }
  }

  public SecretKey getSigningKey(TokenType tokenType) {
    return getSettings(tokenType).secretKey();
  }

  public Duration getValidity(TokenType tokenType) {
    return getSettings(tokenType).validity();
  }

  private JwtTokenSettings getSettings(TokenType tokenType) {
    JwtTokenSettings tokenSettings = settings.get(tokenType);
    if (tokenSettings == null) {
      throw new JwtConfigurationException(
          "No jwt configuration found for token type %s".formatted(tokenType));
    }
    return tokenSettings;
  }

  private record JwtTokenSettings(SecretKey secretKey, Duration validity) {}
}
