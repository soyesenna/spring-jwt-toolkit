package jakarta.persistence;

/**
 * Simplified stub mirroring the subset of the Jakarta Persistence {@code EntityManager} interface
 * needed by the tests.
 */
public interface EntityManager {
  /**
   * Locates the entity with the given identifier.
   */
  <T> T find(Class<T> entityClass, Object primaryKey);
}
