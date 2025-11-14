package com.soyesenna.spring_jwt_toolkit.samples;

import com.soyesenna.spring_jwt_toolkit.annotations.JwtSubject;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import javax.persistence.Id;

public abstract class AbstractJpaEntity {

  @Id
  @JwtSubject(tokenTypes = TokenType.ACCESS)
  private Long id;

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }
}
