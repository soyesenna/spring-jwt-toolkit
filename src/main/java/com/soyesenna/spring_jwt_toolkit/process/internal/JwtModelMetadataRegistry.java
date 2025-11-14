package com.soyesenna.spring_jwt_toolkit.process.internal;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.util.Assert;

public class JwtModelMetadataRegistry {

  private final Map<Class<?>, JwtModelMetadata> cache = new ConcurrentHashMap<>();

  public JwtModelMetadata getMetadata(Class<?> modelClass) {
    Assert.notNull(modelClass, "modelClass must not be null");
    return this.cache.computeIfAbsent(modelClass, JwtModelMetadata::new);
  }
}
