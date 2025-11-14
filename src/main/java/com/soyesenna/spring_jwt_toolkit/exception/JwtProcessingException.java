package com.soyesenna.spring_jwt_toolkit.exception;

public class JwtProcessingException extends JwtToolkitException {

  public JwtProcessingException(String message) {
    super(message);
  }

  public JwtProcessingException(String message, Throwable cause) {
    super(message, cause);
  }
}
