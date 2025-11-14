package com.soyesenna.spring_jwt_toolkit.process.internal;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.util.Assert;

/**
 * Thread-safe cache that stores {@link JwtModelMetadata} for {@code @JwtModel}-annotated classes,
 * ensuring reflective inspection occurs only once per model type.
 */
public class JwtModelMetadataRegistry {

  private final Map<Class<?>, JwtModelMetadata> cache = new ConcurrentHashMap<>();

  /**
   * Returns metadata for the supplied model class, computing and caching it on first access.
   *
   * @param modelClass class annotated with {@code @JwtModel}
   * @return metadata describing subject and claim mappings
   */
  public JwtModelMetadata getMetadata(Class<?> modelClass) {
    Assert.notNull(modelClass, "modelClass must not be null");
    return this.cache.computeIfAbsent(modelClass, JwtModelMetadata::new);
  }
}
