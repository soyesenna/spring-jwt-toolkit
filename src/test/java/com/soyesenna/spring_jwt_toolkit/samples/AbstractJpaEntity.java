package com.soyesenna.spring_jwt_toolkit.samples;

import com.soyesenna.spring_jwt_toolkit.annotations.JwtSubject;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import javax.persistence.Id;

/**
 * Sample mapped superclass used by tests to verify that identifier discovery works when {@code @Id}
 * is declared on a parent class.
 */
public abstract class AbstractJpaEntity {

  @Id
  @JwtSubject(tokenTypes = TokenType.ACCESS)
  private Long id;

  /**
   * @return entity identifier
   */
  public Long getId() {
    return id;
  }

  /**
   * Updates the identifier value for tests.
   *
   * @param id new identifier
   */
  public void setId(Long id) {
    this.id = id;
  }
}
