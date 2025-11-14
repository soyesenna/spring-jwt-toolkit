package com.soyesenna.spring_jwt_toolkit.samples;

import com.soyesenna.spring_jwt_toolkit.annotations.JwtClaim;
import com.soyesenna.spring_jwt_toolkit.annotations.JwtModel;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;

@JwtModel
public class SampleJpaUser extends AbstractJpaEntity {

  @JwtClaim(name = "email", tokenTypes = TokenType.ACCESS)
  private String email;

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }
}
