package com.soyesenna.spring_jwt_toolkit.exception;

/**
 * Indicates that the toolkit detected an invalid configuration or metadata definition. Examples
 * include missing signing keys, duplicate {@code @JwtSubject} fields, or models lacking a default
 * constructor. These errors should be fixed by adjusting application configuration rather than at
 * runtime.
 */
public class JwtConfigurationException extends JwtToolkitException {

  /**
   * Constructs the exception with an explanatory message.
   *
   * @param message detailed configuration error
   */
  public JwtConfigurationException(String message) {
    super(message);
  }
}
