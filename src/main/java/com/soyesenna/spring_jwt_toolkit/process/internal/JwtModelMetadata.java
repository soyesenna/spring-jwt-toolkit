package com.soyesenna.spring_jwt_toolkit.process.internal;

import com.soyesenna.spring_jwt_toolkit.annotations.JwtClaim;
import com.soyesenna.spring_jwt_toolkit.annotations.JwtModel;
import com.soyesenna.spring_jwt_toolkit.annotations.JwtSubject;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.exception.JwtConfigurationException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

public class JwtModelMetadata {

  @Getter
  private final Class<?> modelClass;
  private static final String JPA_ID_ANNOTATION_NAME = "jakarta.persistence.Id";
  @SuppressWarnings("unchecked")
  private static final Class<? extends Annotation> JPA_ID_ANNOTATION_CLASS =
      ClassUtils.isPresent(JPA_ID_ANNOTATION_NAME, JwtModelMetadata.class.getClassLoader())
          ? (Class<? extends Annotation>)
              ClassUtils.resolveClassName(
                  JPA_ID_ANNOTATION_NAME, JwtModelMetadata.class.getClassLoader())
          : null;

  private final Constructor<?> constructor;
  private final Map<TokenType, Field> subjectFields = new EnumMap<>(TokenType.class);
  private final Map<TokenType, List<JwtClaimFieldMetadata>> claimFields = new EnumMap<>(
      TokenType.class);
  private final Field jpaIdField;

  public JwtModelMetadata(Class<?> modelClass) {
    this.modelClass = modelClass;
    if (!modelClass.isAnnotationPresent(JwtModel.class)) {
      throw new JwtConfigurationException(
          "Class %s is not annotated with @JwtModel".formatted(modelClass.getName())
      );
    }

    try {
      this.constructor = modelClass.getDeclaredConstructor();
      ReflectionUtils.makeAccessible(this.constructor);
    } catch (NoSuchMethodException ex) {
      throw new JwtConfigurationException(
          "Class %s must declare a no-args constructor".formatted(modelClass.getName())
      );
    }

    ReflectionUtils.doWithFields(
        modelClass,
        this::registerField,
        field ->
            field.isAnnotationPresent(JwtSubject.class)
                || field.isAnnotationPresent(JwtClaim.class)
    );

    this.jpaIdField = resolveJpaIdField(modelClass);
  }

  private void registerField(Field field) {
    ReflectionUtils.makeAccessible(field);
    if (field.isAnnotationPresent(JwtSubject.class)) {
      this.registerSubjectField(field);
    }
    if (field.isAnnotationPresent(JwtClaim.class)) {
      this.registerClaimField(field);
    }
  }

  private void registerSubjectField(Field field) {
    JwtSubject annotation = field.getAnnotation(JwtSubject.class);
    TokenType[] tokenTypes = annotation.tokenTypes();
    for (TokenType tokenType : tokenTypes) {
      Field existing = this.subjectFields.get(tokenType);
      if (existing != null && existing != field) {
        throw new JwtConfigurationException(
            "Multiple subject fields found for %s on %s"
                .formatted(tokenType, modelClass.getName())
        );
      }
      this.subjectFields.put(tokenType, field);
    }
  }

  private void registerClaimField(Field field) {
    JwtClaim annotation = field.getAnnotation(JwtClaim.class);
    for (TokenType tokenType : annotation.tokenTypes()) {
      this.claimFields
          .computeIfAbsent(tokenType, key -> new ArrayList<>())
          .add(new JwtClaimFieldMetadata(annotation.name(), field));
    }
  }

  private Field resolveJpaIdField(Class<?> type) {
    if (JPA_ID_ANNOTATION_CLASS == null) {
      return null;
    }
    class FieldHolder {
      Field field;
    }
    FieldHolder holder = new FieldHolder();
    ReflectionUtils.doWithFields(
        type,
        field -> {
          if (holder.field == null
              && field.getAnnotation(JPA_ID_ANNOTATION_CLASS) != null) {
            ReflectionUtils.makeAccessible(field);
            holder.field = field;
          }
        });
    return holder.field;
  }

  public Field getSubjectField(TokenType tokenType) {
    return this.subjectFields.get(tokenType);
  }

  public List<JwtClaimFieldMetadata> getClaimFields(TokenType tokenType) {
    return this.claimFields.getOrDefault(tokenType, List.of());
  }

  public Object createInstance() {
    try {
      return this.constructor.newInstance();
    } catch (Exception ex) {
      throw new JwtConfigurationException(
          "Failed to create instance of %s: %s"
              .formatted(modelClass.getName(), ex.getMessage())
      );
    }
  }

  public Field getJpaIdField() {
    return this.jpaIdField;
  }
}
