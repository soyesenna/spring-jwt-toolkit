package com.soyesenna.spring_jwt_toolkit.samples;

import javax.persistence.EntityManager;
import java.util.HashMap;
import java.util.Map;

/**
 * Minimal in-memory {@link EntityManager} implementation used exclusively in unit tests. It allows
 * the toolkit to exercise JPA-specific paths without a real persistence provider.
 */
public class TestEntityManager implements EntityManager {

  private final Map<Object, Object> store = new HashMap<>();

  /**
   * Stores an entity under the provided identifier so a subsequent {@link #find(Class, Object)} call
   * can retrieve it.
   */
  public void persist(Object id, Object entity) {
    store.put(id, entity);
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T> T find(Class<T> entityClass, Object primaryKey) {
    return (T) store.get(primaryKey);
  }
}
