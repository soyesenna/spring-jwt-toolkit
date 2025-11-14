package com.soyesenna.spring_jwt_toolkit.context;

import java.util.Optional;

/**
 * Thread-local holder for {@link HttpRequestContext}.
 */
public final class HttpRequestContextHolder {

  private static final ThreadLocal<HttpRequestContext> CONTEXT = new ThreadLocal<>();

  private HttpRequestContextHolder() {}

  public static void setContext(HttpRequestContext context) {
    CONTEXT.set(context);
  }

  public static void clear() {
    CONTEXT.remove();
  }

  public static Optional<HttpRequestContext> getContext() {
    return Optional.ofNullable(CONTEXT.get());
  }
}
