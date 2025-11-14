package com.soyesenna.spring_jwt_toolkit.exception;

/**
 * Signals runtime issues while generating or extracting JWTs, such as parsing errors or attempts to
 * mint tokens with invalid subject data. These are typically recoverable at runtime by rejecting the
 * offending token.
 */
public class JwtProcessingException extends JwtToolkitException {

  /**
   * Creates a processing exception with message only.
   *
   * @param message human-readable error detail
   */
  public JwtProcessingException(String message) {
    super(message);
  }

  /**
   * Creates a processing exception with both message and underlying cause.
   *
   * @param message error description
   * @param cause root cause
   */
  public JwtProcessingException(String message, Throwable cause) {
    super(message, cause);
  }
}
