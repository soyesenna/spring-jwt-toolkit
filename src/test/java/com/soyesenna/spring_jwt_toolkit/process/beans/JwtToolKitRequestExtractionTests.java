package com.soyesenna.spring_jwt_toolkit.process.beans;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.soyesenna.spring_jwt_toolkit.configuration.JwtProperties;
import com.soyesenna.spring_jwt_toolkit.context.HttpRequestContext;
import com.soyesenna.spring_jwt_toolkit.context.HttpRequestContextHolder;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtModelMetadataRegistry;
import com.soyesenna.spring_jwt_toolkit.process.internal.JwtTokenSettingsProvider;
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
        false,
        null
    );
  }

  @AfterEach
  void tearDown() {
    HttpRequestContextHolder.clear();
  }

  @Test
  void extractsTokensFromRequestContext() {
    HttpRequestContextHolder.setContext(
        new HttpRequestContext(
            Map.of("Authorization", "Bearer bearer.token.value", "X-ACCESS", "header-access"),
            Map.of("payload", "value"),
            Map.of("ACCESS_COOKIE", "cookie-access", "REFRESH_COOKIE", "cookie-refresh")));

    assertThat(this.jwtToolKit.extractFromHeader("x-access")).contains("header-access");
    assertThat(this.jwtToolKit.extractFromBody("payload")).contains("value");
    assertThat(this.jwtToolKit.extractFromCookie("ACCESS_COOKIE")).contains("cookie-access");
    assertThat(this.jwtToolKit.extractFromAuthorizationBearer()).contains("bearer.token.value");

    assertThat(this.jwtToolKit.extractTokenFromHeader(TokenType.ACCESS, "X-ACCESS"))
        .contains("header-access");
    assertThat(this.jwtToolKit.extractAccessTokenFromCookie("ACCESS_COOKIE"))
        .contains("cookie-access");
    assertThat(this.jwtToolKit.extractRefreshTokenFromCookie("REFRESH_COOKIE"))
        .contains("cookie-refresh");
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
}
