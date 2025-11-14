package com.soyesenna.spring_jwt_toolkit.configuration;

import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import java.time.Duration;
import java.util.EnumMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;

/**
 * Strongly typed representation of the {@code jwt.*} configuration tree. The properties control
 * signing keys, token validity, and optional integration points such as JPA. Binding this class via
 * {@link ConfigurationProperties} ensures that validation occurs early in the application start-up
 * lifecycle.
 */
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

  private final TokenSettings access = new TokenSettings();
  private final TokenSettings refresh = new TokenSettings();
  private boolean useJpa = false;

  /**
   * @return configuration for access tokens
   */
  public TokenSettings getAccess() {
    return access;
  }

  /**
   * @return configuration for refresh tokens
   */
  public TokenSettings getRefresh() {
    return refresh;
  }

  /**
   * @return whether the toolkit should attempt to load entities from a JPA {@code EntityManager}
   */
  public boolean isUseJpa() {
    return useJpa;
  }

  /**
   * Enables or disables the optional JPA integration. When enabled, {@code JwtExtractor} will
   * attempt to resolve token bodies by looking up entities via their {@code @Id} field.
   *
   * @param useJpa {@code true} to enable entity lookups, {@code false} to keep pure reflection mode
   */
  public void setUseJpa(boolean useJpa) {
    this.useJpa = useJpa;
  }

  /**
   * Materializes the configured token settings as an immutable {@link Map}. The registry layer uses
   * this view to iterate over every {@link TokenType} without exposing the mutable backing fields.
   *
   * @return immutable view of token settings keyed by {@link TokenType}
   */
  public Map<TokenType, TokenSettings> asMap() {
    Map<TokenType, TokenSettings> map = new EnumMap<>(TokenType.class);
    map.put(TokenType.ACCESS, access);
    map.put(TokenType.REFRESH, refresh);
    return Map.copyOf(map);
  }

  /**
   * Resolves the concrete {@link TokenSettings} for the requested {@link TokenType}. The method
   * performs null-checking to provide immediate feedback when callers accidentally pass {@code null}
   * values.
   *
   * @param tokenType the token type whose settings should be returned
   * @return the strongly typed configuration for the provided token type
   */
  public TokenSettings getSettings(TokenType tokenType) {
    Assert.notNull(tokenType, "tokenType must not be null");
    return switch (tokenType) {
      case ACCESS -> access;
      case REFRESH -> refresh;
    };
  }

  /**
   * Configuration slice containing the signing key and validity duration for a specific token type.
   */
  public static class TokenSettings {

    private String key;
    private Duration validity = Duration.ZERO;

    /**
     * @return the signing key used when generating or verifying a token
     */
    public String getKey() {
      return key;
    }

    /**
     * Updates the signing key. A readable string or Base64-encoded value may be supplied; the
     * {@code JwtTokenSettingsProvider} normalizes the value.
     *
     * @param key raw or Base64-encoded signing key
     */
    public void setKey(String key) {
      this.key = key;
    }

    /**
     * @return the duration for which tokens of this type remain valid
     */
    public Duration getValidity() {
      return validity;
    }

    /**
     * Sets the validity duration. Validation later in the pipeline ensures the duration is positive
     * and non-zero.
     *
     * @param validity requested token lifetime
     */
    public void setValidity(Duration validity) {
      this.validity = validity;
    }
  }
}
