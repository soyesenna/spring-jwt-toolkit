package com.soyesenna.spring_jwt_toolkit.process.beans;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.annotations.JwtModel;
import com.soyesenna.spring_jwt_toolkit.configuration.JwtProperties;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.samples.AbstractJpaEntity;
import com.soyesenna.spring_jwt_toolkit.process.internal.JpaEntityProvider;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadata;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadataRegistry;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtTokenSettingsProvider;
import com.soyesenna.spring_jwt_toolkit.samples.SampleJpaUser;
import com.soyesenna.spring_jwt_toolkit.samples.TestEntityManager;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * Unit tests proving that {@link JwtToolKit} correctly resolves entities via the optional JPA
 * integration and can detect identifier fields declared on mapped superclasses.
 */
class JwtToolKitJpaTests {

  /**
   * Ensures that when models opt into JPA via {@code @JwtModel(useJpa = true)} the toolkit replaces
   * the reflectively populated body with the entity loaded from the
   * {@link jakarta.persistence.EntityManager}.
   */
  @Test
  void extractUsesJpaEntityWhenEnabled() {
    JwtModelMetadataRegistry metadataRegistry = new JwtModelMetadataRegistry();
    JwtProperties properties = jwtProperties();
    JwtTokenSettingsProvider tokenSettingsProvider = new JwtTokenSettingsProvider(properties);
    ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    SampleJpaUser tokenUser = new SampleJpaUser();
    tokenUser.setId(42L);
    tokenUser.setEmail("token@sample.com");

    SampleJpaUser persistedUser = new SampleJpaUser();
    persistedUser.setId(42L);
    persistedUser.setEmail("persisted@sample.com");
    TestEntityManager entityManager = new TestEntityManager();
    entityManager.persist(persistedUser.getId(), persistedUser);

    JpaEntityProvider provider = JpaEntityProvider.fromEntityManager(entityManager);
    assertThat(provider).isNotNull();

    JwtToolKit jwtToolKit =
        new JwtToolKit(
            metadataRegistry,
            tokenSettingsProvider,
            objectMapper,
            provider);

    String token = jwtToolKit.generateTokenValue(tokenUser, TokenType.ACCESS);

    JwtExtractionResult<SampleJpaUser> result =
        jwtToolKit.extract(token, TokenType.ACCESS, SampleJpaUser.class);

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

  @Test
  void extractSkipsJpaWhenModelDoesNotOptIn() {
    JwtModelMetadataRegistry metadataRegistry = new JwtModelMetadataRegistry();
    JwtTokenSettingsProvider tokenSettingsProvider = new JwtTokenSettingsProvider(jwtProperties());
    ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    NonJpaModel tokenUser = new NonJpaModel();
    tokenUser.setId(55L);

    NonJpaModel persisted = new NonJpaModel();
    persisted.setId(55L);

    TestEntityManager entityManager = new TestEntityManager();
    entityManager.persist(persisted.getId(), persisted);

    JpaEntityProvider provider = JpaEntityProvider.fromEntityManager(entityManager);
    assertThat(provider).isNotNull();

    JwtToolKit jwtToolKit =
        new JwtToolKit(
            metadataRegistry,
            tokenSettingsProvider,
            objectMapper,
            provider);

    String token = jwtToolKit.generateTokenValue(tokenUser, TokenType.ACCESS);

    JwtExtractionResult<NonJpaModel> result =
        jwtToolKit.extract(token, TokenType.ACCESS, NonJpaModel.class);

    assertThat(result.body())
        .isNotSameAs(persisted)
        .extracting(NonJpaModel::getId)
        .isEqualTo(55L);
  }

  /**
   * Creates a {@link JwtProperties} instance suitable for use in unit tests.
   */
  private JwtProperties jwtProperties() {
    JwtProperties properties = new JwtProperties();
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

  @JwtModel
  static class NonJpaModel extends AbstractJpaEntity {}
}
