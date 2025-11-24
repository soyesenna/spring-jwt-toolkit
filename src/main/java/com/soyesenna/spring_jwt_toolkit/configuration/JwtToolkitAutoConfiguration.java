package com.soyesenna.spring_jwt_toolkit.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.context.HttpRequestContextFilter;
import com.soyesenna.spring_jwt_toolkit.process.beans.JwtToolKit;
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
   * Exposes the consolidated {@link JwtToolKit} bean that applications can inject to mint, parse,
   * and authenticate JWTs.
   *
   * @param metadataRegistry cached metadata
   * @param tokenSettingsProvider provider for signing keys
   * @param objectMapper mapper used for claim conversion
   * @param applicationContext allows detection of a hosted {@code EntityManager}
   * @return the toolkit bean the library provides
   */
  @Bean
  @ConditionalOnMissingBean
  public JwtToolKit jwtToolKit(
      JwtModelMetadataRegistry metadataRegistry,
      JwtTokenSettingsProvider tokenSettingsProvider,
      ObjectMapper objectMapper,
      ApplicationContext applicationContext
  ) {
    JpaEntityProvider entityProvider =
        JpaEntityProvider.fromApplicationContext(applicationContext);
    return new JwtToolKit(
        metadataRegistry,
        tokenSettingsProvider,
        objectMapper,
        entityProvider);
  }

  @Bean
  @ConditionalOnMissingBean
  public HttpRequestContextFilter httpRequestContextFilter(ObjectMapper objectMapper) {
    return new HttpRequestContextFilter(objectMapper);
  }
}
