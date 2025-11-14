package javax.persistence;

/**
 * Legacy Java EE counterpart to the Jakarta Persistence {@code EntityManager} stub.
 */
public interface EntityManager {
  /**
   * Locates an entity by identifier.
   */
  <T> T find(Class<T> entityClass, Object primaryKey);
}
