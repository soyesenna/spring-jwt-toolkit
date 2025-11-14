package com.soyesenna.spring_jwt_toolkit.exception;

public class JwtToolkitException extends RuntimeException {

  public JwtToolkitException(String message) {
    super(message);
  }

  public JwtToolkitException(String message, Throwable cause) {
    super(message, cause);
  }
}
