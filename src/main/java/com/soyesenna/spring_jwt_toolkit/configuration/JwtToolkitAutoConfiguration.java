package com.soyesenna.spring_jwt_toolkit.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.process.beans.JwtAuthenticator;
import com.soyesenna.spring_jwt_toolkit.process.beans.JwtExtractor;
import com.soyesenna.spring_jwt_toolkit.process.beans.JwtGenerator;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadataRegistry;
import com.soyesenna.spring_jwt_toolkit.process.internal.JpaEntityProvider;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtTokenSettingsProvider;
import io.jsonwebtoken.Jwts;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Boot auto-configuration that wires the toolkit's beans when {@link Jwts} is present on the
 * classpath. Each {@code @Bean} declaration is guarded by {@link ConditionalOnMissingBean} so that
 * host applications can override specific components as needed while still benefitting from the
 * sensible defaults.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(Jwts.class)
@EnableConfigurationProperties(JwtProperties.class)
public class JwtToolkitAutoConfiguration {

  /**
   * Creates a singleton registry that caches {@link com.soyesenna.spring_jwt_toolkit.annotations.JwtModel}
   * metadata for repeated use.
   *
   * @return a reusable metadata registry
   */
  @Bean
  @ConditionalOnMissingBean
  public JwtModelMetadataRegistry jwtModelMetadataRegistry() {
    return new JwtModelMetadataRegistry();
  }

  /**
   * Initializes the provider responsible for validating and exposing token signing keys and
   * lifetimes.
   *
   * @param properties bound JWT configuration
   * @return a constructed {@link JwtTokenSettingsProvider}
   */
  @Bean
  @ConditionalOnMissingBean
  public JwtTokenSettingsProvider jwtTokenSettingsProvider(JwtProperties properties) {
    return new JwtTokenSettingsProvider(properties);
  }

  /**
   * Supplies a default {@link ObjectMapper} for converting claim bodies. The mapper dynamically
   * registers all discovered modules (e.g., Java Time) so model classes can leverage modern types.
   *
   * @return configured object mapper
   */
  @Bean
  @ConditionalOnMissingBean
  public ObjectMapper jwtToolkitObjectMapper() {
    return new ObjectMapper().findAndRegisterModules();
  }

  /**
   * Exposes the {@link JwtGenerator} bean that applications can inject to mint tokens.
   *
   * @param metadataRegistry cached metadata
   * @param tokenSettingsProvider provider for signing keys and validity
   * @param objectMapper mapper used for claim conversion
   * @return a fully initialized generator
   */
  @Bean
  @ConditionalOnMissingBean
  public JwtGenerator jwtGenerator(
      JwtModelMetadataRegistry metadataRegistry,
      JwtTokenSettingsProvider tokenSettingsProvider,
      ObjectMapper objectMapper
  ) {
    return new JwtGenerator(metadataRegistry, tokenSettingsProvider, objectMapper);
  }

  /**
   * Exposes the {@link JwtExtractor}, optionally enabling JPA-backed lookups when configured.
   *
   * @param metadataRegistry cached metadata
   * @param tokenSettingsProvider provider for signing keys
   * @param objectMapper mapper used for deserializing custom claim payloads
   * @param properties toolkit configuration, including the {@code use-jpa} flag
   * @param applicationContext allows detection of a hosted {@code EntityManager}
   * @return the extractor bean the toolkit relies on
   */
  @Bean
  @ConditionalOnMissingBean
  public JwtExtractor jwtExtractor(
      JwtModelMetadataRegistry metadataRegistry,
      JwtTokenSettingsProvider tokenSettingsProvider,
      ObjectMapper objectMapper,
      JwtProperties properties,
      ApplicationContext applicationContext
  ) {
    JpaEntityProvider entityProvider =
        JpaEntityProvider.fromApplicationContext(applicationContext);
    return new JwtExtractor(
        metadataRegistry,
        tokenSettingsProvider,
        objectMapper,
        properties.isUseJpa(),
        entityProvider);
  }

  /**
   * Publishes a reusable {@link JwtAuthenticator} so integrations with Spring Security can convert
   * opaque JWT strings into {@link org.springframework.security.core.Authentication} instances.
   *
   * @param jwtExtractor extractor dependency injected by Spring
   * @return an authenticator ready for use in authentication flows
   */
  @Bean
  @ConditionalOnMissingBean
  public JwtAuthenticator jwtAuthenticator(JwtExtractor jwtExtractor) {
    return new JwtAuthenticator(jwtExtractor);
  }
}
