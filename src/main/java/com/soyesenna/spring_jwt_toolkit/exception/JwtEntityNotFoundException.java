package com.soyesenna.spring_jwt_toolkit.exception;

/**
 * Thrown when a JPA entity lookup is requested via {@code @JwtModel(useJpa = true)} but the
 * {@link jakarta.persistence.EntityManager} returns {@code null} for the extracted identifier.
 * This exception indicates the token references an entity that no longer exists in the database.
 */
public class JwtEntityNotFoundException extends JwtProcessingException {

  private final Class<?> entityClass;
  private final Object identifier;

  /**
   * Creates an exception describing the failed entity lookup.
   *
   * @param entityClass the JPA entity type that was queried
   * @param identifier the primary key extracted from the JWT
   */
  public JwtEntityNotFoundException(Class<?> entityClass, Object identifier) {
    super("Entity of type %s with identifier [%s] not found".formatted(
        entityClass.getName(), identifier));
    this.entityClass = entityClass;
    this.identifier = identifier;
  }

  /**
   * @return the entity class that was requested
   */
  public Class<?> getEntityClass() {
    return entityClass;
  }

  /**
   * @return the primary key value used in the lookup
   */
  public Object getIdentifier() {
    return identifier;
  }
}
