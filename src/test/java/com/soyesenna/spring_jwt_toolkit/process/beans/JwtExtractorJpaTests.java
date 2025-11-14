package com.soyesenna.spring_jwt_toolkit.process.beans;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.configuration.JwtProperties;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.process.internal.JpaEntityProvider;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadataRegistry;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtTokenSettingsProvider;
import com.soyesenna.spring_jwt_toolkit.samples.SampleJpaUser;
import com.soyesenna.spring_jwt_toolkit.samples.TestEntityManager;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * Unit tests proving that {@link JwtExtractor} correctly resolves entities via the optional JPA
 * integration and can detect identifier fields declared on mapped superclasses.
 */
class JwtExtractorJpaTests {

  /**
   * Ensures that when {@code use-jpa=true} the extractor replaces the reflectively populated body
   * with the entity loaded from the {@link jakarta.persistence.EntityManager}.
   */
  @Test
  void extractUsesJpaEntityWhenEnabled() {
    JwtModelMetadataRegistry metadataRegistry = new JwtModelMetadataRegistry();
    JwtProperties properties = jwtProperties(true);
    JwtTokenSettingsProvider tokenSettingsProvider = new JwtTokenSettingsProvider(properties);
    ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
    JwtGenerator generator =
        new JwtGenerator(metadataRegistry, tokenSettingsProvider, objectMapper);

    SampleJpaUser tokenUser = new SampleJpaUser();
    tokenUser.setId(42L);
    tokenUser.setEmail("token@sample.com");
    String token = generator.generateTokenValue(tokenUser, TokenType.ACCESS);

    SampleJpaUser persistedUser = new SampleJpaUser();
    persistedUser.setId(42L);
    persistedUser.setEmail("persisted@sample.com");
    TestEntityManager entityManager = new TestEntityManager();
    entityManager.persist(persistedUser.getId(), persistedUser);

    JpaEntityProvider provider = JpaEntityProvider.fromEntityManager(entityManager);
    assertThat(provider).isNotNull();

    JwtExtractor extractor =
        new JwtExtractor(
            metadataRegistry,
            tokenSettingsProvider,
            objectMapper,
            true,
            provider);

    JwtExtractionResult<SampleJpaUser> result =
        extractor.extract(token, TokenType.ACCESS, SampleJpaUser.class);

    assertThat(result.body()).isSameAs(persistedUser);
    assertThat(result.claims().getSubject()).isEqualTo("42");
  }

  /**
   * Verifies that {@link JwtModelMetadata} can find {@code @Id} annotations declared on
   * superclasses rather than the concrete entity type.
   */
  @Test
  void metadataFindsJpaIdFieldInSuperclass() {
    JwtModelMetadataRegistry registry = new JwtModelMetadataRegistry();
    assertThat(registry.getMetadata(SampleJpaUser.class).getJpaIdField())
        .isNotNull()
        .extracting(Field::getName)
        .isEqualTo("id");
  }

  /**
   * Creates a {@link JwtProperties} instance suitable for use in unit tests.
   */
  private JwtProperties jwtProperties(boolean useJpa) {
    JwtProperties properties = new JwtProperties();
    properties.setUseJpa(useJpa);
    String accessKey =
        Base64.getEncoder().encodeToString("access-secret-key-value-0123456789".getBytes());
    String refreshKey =
        Base64.getEncoder().encodeToString("refresh-secret-key-value-0123456789".getBytes());
    properties.getAccess().setKey(accessKey);
    properties.getAccess().setValidity(Duration.ofMinutes(5));
    properties.getRefresh().setKey(refreshKey);
    properties.getRefresh().setValidity(Duration.ofMinutes(5));
    return properties;
  }
}
