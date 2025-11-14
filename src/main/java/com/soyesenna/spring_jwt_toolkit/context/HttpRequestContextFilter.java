package com.soyesenna.spring_jwt_toolkit.context;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Captures request metadata and stores it in {@link HttpRequestContextHolder}.
 */
public class HttpRequestContextFilter extends OncePerRequestFilter {

  private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

  private final ObjectMapper objectMapper;

  public HttpRequestContextFilter(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    CachedBodyHttpServletRequest wrappedRequest = new CachedBodyHttpServletRequest(request);
    HttpRequestContextHolder.setContext(buildContext(wrappedRequest));
    try {
      filterChain.doFilter(wrappedRequest, response);
    } finally {
      HttpRequestContextHolder.clear();
    }
  }

  private HttpRequestContext buildContext(CachedBodyHttpServletRequest request)
      throws IOException {
    Map<String, String> headers = extractHeaders(request);
    Map<String, Object> body = extractBody(request);
    Map<String, String> cookies = extractCookies(request);
    return new HttpRequestContext(headers, body, cookies);
  }

  private Map<String, String> extractHeaders(HttpServletRequest request) {
    Map<String, String> headers = new HashMap<>();
    Enumeration<String> names = request.getHeaderNames();
    while (names.hasMoreElements()) {
      String name = names.nextElement();
      headers.put(name, request.getHeader(name));
    }
    return headers;
  }

  private Map<String, Object> extractBody(CachedBodyHttpServletRequest request) {
    byte[] body = request.getCachedBody();
    if (body.length == 0) {
      return Collections.emptyMap();
    }
    String contentType = request.getContentType();
    if (contentType != null && contentType.toLowerCase(Locale.ENGLISH).contains("application/json")) {
      try {
        return objectMapper.readValue(body, MAP_TYPE);
      } catch (IOException ex) {
        return Collections.emptyMap();
      }
    }
    return Collections.singletonMap("raw", new String(body, StandardCharsets.UTF_8));
  }

  private Map<String, String> extractCookies(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null || cookies.length == 0) {
      return Collections.emptyMap();
    }
    Map<String, String> result = new HashMap<>();
    for (Cookie cookie : cookies) {
      result.put(cookie.getName(), cookie.getValue());
    }
    return result;
  }
}
