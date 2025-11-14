package com.soyesenna.spring_jwt_toolkit.exception;

/**
 * Indicates that a JWT failed structural validation or signature checks.
 */
public class JwtInvalidException extends JwtProcessingException {

  public JwtInvalidException(String message, Throwable cause) {
    super(message, cause);
  }
}
