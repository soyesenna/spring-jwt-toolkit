package com.soyesenna.spring_jwt_toolkit.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.process.JwtAuthenticator;
import com.soyesenna.spring_jwt_toolkit.process.JwtExtractor;
import com.soyesenna.spring_jwt_toolkit.process.JwtGenerator;
import com.soyesenna.spring_jwt_toolkit.process.JwtModelMetadataRegistry;
import com.soyesenna.spring_jwt_toolkit.process.JwtTokenSettingsProvider;
import io.jsonwebtoken.Jwts;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(Jwts.class)
@EnableConfigurationProperties(JwtProperties.class)
public class JwtToolkitAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public JwtModelMetadataRegistry jwtModelMetadataRegistry() {
    return new JwtModelMetadataRegistry();
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtTokenSettingsProvider jwtTokenSettingsProvider(JwtProperties properties) {
    return new JwtTokenSettingsProvider(properties);
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtGenerator jwtGenerator(
      JwtModelMetadataRegistry metadataRegistry,
      JwtTokenSettingsProvider tokenSettingsProvider,
      ObjectMapper objectMapper
  ) {
    return new JwtGenerator(metadataRegistry, tokenSettingsProvider, objectMapper);
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtExtractor jwtExtractor(
      JwtModelMetadataRegistry metadataRegistry,
      JwtTokenSettingsProvider tokenSettingsProvider,
      ObjectMapper objectMapper
  ) {
    return new JwtExtractor(metadataRegistry, tokenSettingsProvider, objectMapper);
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtAuthenticator jwtAuthenticator(JwtExtractor jwtExtractor) {
    return new JwtAuthenticator(jwtExtractor);
  }
}
