package jakarta.persistence;

public interface EntityManager {
  <T> T find(Class<T> entityClass, Object primaryKey);
}
