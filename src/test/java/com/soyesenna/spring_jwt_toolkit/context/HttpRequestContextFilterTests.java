package com.soyesenna.spring_jwt_toolkit.context;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class HttpRequestContextFilterTests {

  private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

  @Test
  void capturesHeadersBodyAndCookies() throws ServletException, IOException {
    HttpRequestContextFilter filter = new HttpRequestContextFilter(objectMapper);
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setMethod("POST");
    request.setContentType("application/json");
    request.setContent("""
        {"email":"token@sample.com"}
        """.getBytes());
    request.addHeader("X-Test", "alpha");
    request.addHeader("Authorization", "Bearer abc.def.ghi");
    request.setCookies(new Cookie("session", "cookie-value"));
    MockHttpServletResponse response = new MockHttpServletResponse();

    filter.doFilter(
        request,
        response,
        (req, res) -> {
          HttpRequestContext ctx = HttpRequestContextHolder.getContext().orElseThrow();
          assertThat(ctx.headers()).containsEntry("X-Test", "alpha");
          assertThat(ctx.body()).containsEntry("email", "token@sample.com");
          assertThat(ctx.cookies()).containsEntry("session", "cookie-value");
        });

    assertThat(HttpRequestContextHolder.getContext()).isEmpty();
  }
}
