package com.soyesenna.spring_jwt_toolkit.samples;

import com.soyesenna.spring_jwt_toolkit.annotations.JwtClaim;
import com.soyesenna.spring_jwt_toolkit.annotations.JwtModel;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;

/**
 * Simple model used within tests to generate and extract JWTs while exercising the JPA lookup code.
 */
@JwtModel
public class SampleJpaUser extends AbstractJpaEntity {

  @JwtClaim(name = "email", tokenTypes = TokenType.ACCESS)
  private String email;

  /**
   * @return email claim value
   */
  public String getEmail() {
    return email;
  }

  /**
   * Sets the email claim used when generating tokens.
   *
   * @param email email address
   */
  public void setEmail(String email) {
    this.email = email;
  }
}
