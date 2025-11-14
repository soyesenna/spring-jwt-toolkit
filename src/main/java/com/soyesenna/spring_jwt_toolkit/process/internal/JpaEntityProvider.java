package com.soyesenna.spring_jwt_toolkit.process.internal;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

/**
 * Reflection-based adapter around a JPA {@code EntityManager}. The provider is created only when a
 * host application includes JPA and exposes an {@code EntityManager} bean, keeping the toolkit
 * optional-dependency friendly.
 */
public final class JpaEntityProvider {

  private static final List<String> ENTITY_MANAGER_CLASS_NAMES =
      List.of("jakarta.persistence.EntityManager", "javax.persistence.EntityManager");

  private final Object entityManager;
  private final Method findMethod;

  private JpaEntityProvider(Object entityManager, Method findMethod) {
    this.entityManager = entityManager;
    this.findMethod = findMethod;
  }

  /**
   * Attempts to create a provider using any {@code EntityManager} bean available in the context.
   *
   * @param context application context used to resolve beans
   * @return provider instance or {@code null} when no entity manager is available
   */
  @Nullable
  public static JpaEntityProvider fromApplicationContext(ApplicationContext context) {
    Class<?> entityManagerClass = resolveEntityManagerClass(context.getClassLoader());
    if (entityManagerClass == null) {
      return null;
    }
    Object entityManager = context.getBeanProvider(entityManagerClass).getIfAvailable();
    if (entityManager == null) {
      return null;
    }
    return fromEntityManager(entityManager);
  }

  /**
   * Creates a provider backed by the supplied entity manager instance.
   *
   * @param entityManager actual entity manager implementation
   * @return provider or {@code null} if a usable {@code find} method cannot be located
   */
  @Nullable
  public static JpaEntityProvider fromEntityManager(Object entityManager) {
    Method method = resolveFindMethod(entityManager);
    if (method == null) {
      return null;
    }
    ReflectionUtils.makeAccessible(method);
    return new JpaEntityProvider(entityManager, method);
  }

  /**
   * Finds an entity of the requested type using the provided identifier.
   *
   * @param entityClass JPA entity type to load
   * @param id primary key extracted from the JWT model
   * @return optional containing the entity if found
   */
  public Optional<Object> findEntity(Class<?> entityClass, Object id) {
    if (entityClass == null || id == null) {
      return Optional.empty();
    }
    Object result = ReflectionUtils.invokeMethod(this.findMethod, this.entityManager, entityClass, id);
    return Optional.ofNullable(result);
  }

  /**
   * Locates a {@code find(Class, Object)} method on either the implementation or its interfaces.
   */
  @Nullable
  private static Method resolveFindMethod(Object entityManager) {
    Method method =
        ReflectionUtils.findMethod(entityManager.getClass(), "find", Class.class, Object.class);
    if (method != null) {
      return method;
    }
    for (Class<?> candidate : ClassUtils.getAllInterfaces(entityManager)) {
      method = ReflectionUtils.findMethod(candidate, "find", Class.class, Object.class);
      if (method != null) {
        return method;
      }
    }
    return null;
  }

  /**
   * Resolves the {@code EntityManager} class present on the classpath if any.
   */
  @Nullable
  private static Class<?> resolveEntityManagerClass(ClassLoader classLoader) {
    for (String className : ENTITY_MANAGER_CLASS_NAMES) {
      if (ClassUtils.isPresent(className, classLoader)) {
        return ClassUtils.resolveClassName(className, classLoader);
      }
    }
    return null;
  }
}
