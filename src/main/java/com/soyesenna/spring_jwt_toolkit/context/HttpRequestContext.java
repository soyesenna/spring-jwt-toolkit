package com.soyesenna.spring_jwt_toolkit.context;

import java.util.Collections;
import java.util.Map;

/**
 * Immutable snapshot of an {@link jakarta.servlet.http.HttpServletRequest}.
 */
public record HttpRequestContext(
    Map<String, String> headers,
    Map<String, Object> body,
    Map<String, String> cookies
) {

  public HttpRequestContext {
    headers = headers == null ? Map.of() : Collections.unmodifiableMap(headers);
    body = body == null ? Map.of() : Collections.unmodifiableMap(body);
    cookies = cookies == null ? Map.of() : Collections.unmodifiableMap(cookies);
  }
}
