package com.soyesenna.spring_jwt_toolkit.process.beans;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.annotations.JwtModel;
import com.soyesenna.spring_jwt_toolkit.annotations.JwtSubject;
import com.soyesenna.spring_jwt_toolkit.configuration.JwtProperties;
import com.soyesenna.spring_jwt_toolkit.context.HttpRequestContext;
import com.soyesenna.spring_jwt_toolkit.context.HttpRequestContextHolder;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.process.internal.JpaEntityProvider;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadataRegistry;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtTokenSettingsProvider;
import com.soyesenna.spring_jwt_toolkit.samples.SampleJpaUser;
import com.soyesenna.spring_jwt_toolkit.samples.TestEntityManager;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JwtToolKitRequestExtractionTests {

  private JwtToolKit jwtToolKit;

  @BeforeEach
  void setUp() {
    this.jwtToolKit = new JwtToolKit(
        new JwtModelMetadataRegistry(),
        new JwtTokenSettingsProvider(jwtProperties()),
        new ObjectMapper().findAndRegisterModules(),
        null
    );
  }

  @AfterEach
  void tearDown() {
    HttpRequestContextHolder.clear();
  }

  @Test
  void extractsBearerTokensByTypeFromRequestContext() {
    DualTokenModel model = new DualTokenModel();
    model.setUserId(99L);

    String accessToken = this.jwtToolKit.generateTokenValue(model, TokenType.ACCESS);
    String refreshToken = this.jwtToolKit.generateTokenValue(model, TokenType.REFRESH);

    HttpRequestContextHolder.setContext(
        new HttpRequestContext(Map.of("Authorization", "Bearer " + accessToken), Map.of(), Map.of()));

    JwtExtractionResult<DualTokenModel> accessResult =
        this.jwtToolKit.extractAccessTokenFromAuthorizationBearer(DualTokenModel.class)
            .orElseThrow();
    assertThat(accessResult.token()).isEqualTo(accessToken);
    assertThat(accessResult.body().getUserId()).isEqualTo(99L);

    HttpRequestContextHolder.setContext(
        new HttpRequestContext(Map.of("Authorization", "Bearer " + refreshToken), Map.of(), Map.of()));

    JwtExtractionResult<DualTokenModel> refreshResult =
        this.jwtToolKit.extractRefreshTokenFromAuthorizationBearer(DualTokenModel.class)
            .orElseThrow();
    assertThat(refreshResult.token()).isEqualTo(refreshToken);
    assertThat(refreshResult.body().getUserId()).isEqualTo(99L);
  }

  @Test
  void extractsTokensFromRequestBody() {
    DualTokenModel model = new DualTokenModel();
    model.setUserId(77L);
    String refreshToken = this.jwtToolKit.generateTokenValue(model, TokenType.REFRESH);

    HttpRequestContextHolder.setContext(
        new HttpRequestContext(Map.of(), Map.of("refreshToken", refreshToken), Map.of()));

    JwtExtractionResult<DualTokenModel> result =
        this.jwtToolKit.extractRefreshTokenFromBody("refreshToken", DualTokenModel.class)
            .orElseThrow();

    assertThat(result.body().getUserId()).isEqualTo(77L);
    assertThat(result.token()).isEqualTo(refreshToken);
  }

  @Test
  void requestContextExtractionHydratesModelsViaJpaWhenEnabled() {
    JwtModelMetadataRegistry metadataRegistry = new JwtModelMetadataRegistry();
    JwtTokenSettingsProvider tokenSettingsProvider = new JwtTokenSettingsProvider(jwtProperties());
    ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    SampleJpaUser persisted = new SampleJpaUser();
    persisted.setId(7L);
    persisted.setEmail("persisted@request.test");

    SampleJpaUser tokenUser = new SampleJpaUser();
    tokenUser.setId(persisted.getId());
    tokenUser.setEmail("token@request.test");

    TestEntityManager entityManager = new TestEntityManager();
    entityManager.persist(persisted.getId(), persisted);
    JpaEntityProvider jpaEntityProvider = JpaEntityProvider.fromEntityManager(entityManager);
    assertThat(jpaEntityProvider).isNotNull();

    JwtToolKit jpaEnabled =
        new JwtToolKit(
            metadataRegistry,
            tokenSettingsProvider,
            objectMapper,
            jpaEntityProvider);

    String token = jpaEnabled.generateTokenValue(tokenUser, TokenType.ACCESS);

    HttpRequestContextHolder.setContext(
        new HttpRequestContext(
            Map.of("Authorization", "Bearer " + token, "X-ACCESS", token),
            Map.of(),
            Map.of("ACCESS_COOKIE", token)));

    JwtExtractionResult<SampleJpaUser> headerResult =
        jpaEnabled.extractAccessTokenFromHeader("X-ACCESS", SampleJpaUser.class)
            .orElseThrow();
    assertThat(headerResult.body()).isSameAs(persisted);

    JwtExtractionResult<SampleJpaUser> cookieResult =
        jpaEnabled.extractAccessTokenFromCookie("ACCESS_COOKIE", SampleJpaUser.class)
            .orElseThrow();
    assertThat(cookieResult.body()).isSameAs(persisted);

    JwtExtractionResult<SampleJpaUser> bearerResult =
        jpaEnabled.extractAccessTokenFromAuthorizationBearer(SampleJpaUser.class)
            .orElseThrow();
    assertThat(bearerResult.body()).isSameAs(persisted);
  }

  private JwtProperties jwtProperties() {
    JwtProperties properties = new JwtProperties();
    String accessKey =
        Base64.getEncoder()
            .encodeToString("request-access-key-0123456789-ABCDEFGHIJ".getBytes());
    String refreshKey =
        Base64.getEncoder()
            .encodeToString("request-refresh-key-0123456789-ABCDEFGHIJ".getBytes());
    properties.getAccess().setKey(accessKey);
    properties.getAccess().setValidity(Duration.ofMinutes(5));
    properties.getRefresh().setKey(refreshKey);
    properties.getRefresh().setValidity(Duration.ofMinutes(5));
    return properties;
  }

  @JwtModel
  static class DualTokenModel {

    @JwtSubject(tokenTypes = {TokenType.ACCESS, TokenType.REFRESH})
    private Long userId;

    Long getUserId() {
      return userId;
    }

    void setUserId(Long userId) {
      this.userId = userId;
    }
  }
}
