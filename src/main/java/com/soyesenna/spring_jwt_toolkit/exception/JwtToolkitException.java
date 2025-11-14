package com.soyesenna.spring_jwt_toolkit.exception;

/**
 * Base unchecked exception for all toolkit-specific failures. Subclasses communicate whether an
 * error stems from misconfiguration or runtime processing issues and allow callers to catch a
 * single type if they prefer coarse-grained handling.
 */
public class JwtToolkitException extends RuntimeException {

  /**
   * Creates an exception with the supplied message.
   *
   * @param message human-readable description of the failure
   */
  public JwtToolkitException(String message) {
    super(message);
  }

  /**
   * Creates an exception with both message and cause.
   *
   * @param message short description of the problem
   * @param cause the originating exception
   */
  public JwtToolkitException(String message, Throwable cause) {
    super(message, cause);
  }
}
