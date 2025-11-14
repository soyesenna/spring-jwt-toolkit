package com.soyesenna.spring_jwt_toolkit.exception;

/**
 * Indicates that a JWT has exceeded its validity window.
 */
public class JwtExpiredException extends JwtProcessingException {

  public JwtExpiredException(String message, Throwable cause) {
    super(message, cause);
  }
}
