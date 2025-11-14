package com.soyesenna.spring_jwt_toolkit.enums;

/**
 * Enumerates the token lifecycles that the toolkit supports out of the box. The distinction allows
 * separate cryptographic keys and validity settings to be configured for short-lived access tokens
 * versus long-lived refresh tokens.
 */
public enum TokenType {

  /** Represents an access token that is typically sent with API requests. */
  ACCESS,
  /** Represents a refresh token used to mint new access tokens once the old one expires. */
  REFRESH
}
