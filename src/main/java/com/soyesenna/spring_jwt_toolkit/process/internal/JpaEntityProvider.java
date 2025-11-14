package com.soyesenna.spring_jwt_toolkit.process.internal;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;
import org.springframework.context.ApplicationContext;
import org.springframework.lang.Nullable;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

public final class JpaEntityProvider {

  private static final List<String> ENTITY_MANAGER_CLASS_NAMES =
      List.of("jakarta.persistence.EntityManager", "javax.persistence.EntityManager");

  private final Object entityManager;
  private final Method findMethod;

  private JpaEntityProvider(Object entityManager, Method findMethod) {
    this.entityManager = entityManager;
    this.findMethod = findMethod;
  }

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

  @Nullable
  public static JpaEntityProvider fromEntityManager(Object entityManager) {
    Method method = resolveFindMethod(entityManager);
    if (method == null) {
      return null;
    }
    ReflectionUtils.makeAccessible(method);
    return new JpaEntityProvider(entityManager, method);
  }

  public Optional<Object> findEntity(Class<?> entityClass, Object id) {
    if (entityClass == null || id == null) {
      return Optional.empty();
    }
    Object result = ReflectionUtils.invokeMethod(this.findMethod, this.entityManager, entityClass, id);
    return Optional.ofNullable(result);
  }

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
