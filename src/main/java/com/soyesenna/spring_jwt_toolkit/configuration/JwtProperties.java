package com.soyesenna.spring_jwt_toolkit.configuration;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import java.time.Duration;
import java.util.EnumMap;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;

@Getter
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

  private final TokenSettings access = new TokenSettings();
  private final TokenSettings refresh = new TokenSettings();

  public Map<TokenType, TokenSettings> asMap() {
    Map<TokenType, TokenSettings> map = new EnumMap<>(TokenType.class);
    map.put(TokenType.ACCESS, access);
    map.put(TokenType.REFRESH, refresh);
    return Map.copyOf(map);
  }

  public TokenSettings getSettings(TokenType tokenType) {
    Assert.notNull(tokenType, "tokenType must not be null");
    return switch (tokenType) {
      case ACCESS -> access;
      case REFRESH -> refresh;
    };
  }

  @Getter @Setter
  public static class TokenSettings {

    private String key;
    private Duration validity = Duration.ZERO;
  }
}
