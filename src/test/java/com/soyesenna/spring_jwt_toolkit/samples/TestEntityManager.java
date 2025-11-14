package com.soyesenna.spring_jwt_toolkit.samples;

import jakarta.persistence.EntityManager;
import java.util.HashMap;
import java.util.Map;

public class TestEntityManager implements EntityManager {

  private final Map<Object, Object> store = new HashMap<>();

  public void persist(Object id, Object entity) {
    store.put(id, entity);
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T> T find(Class<T> entityClass, Object primaryKey) {
    return (T) store.get(primaryKey);
  }
}
