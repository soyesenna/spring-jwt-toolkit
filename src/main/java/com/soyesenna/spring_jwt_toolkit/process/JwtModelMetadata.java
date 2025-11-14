package com.soyesenna.spring_jwt_toolkit.process;

import com.soyesenna.spring_jwt_toolkit.annotations.JwtClaim;
import com.soyesenna.spring_jwt_toolkit.annotations.JwtModel;
import com.soyesenna.spring_jwt_toolkit.annotations.JwtSubject;
import com.soyesenna.spring_jwt_toolkit.enums.TokenType;
import com.soyesenna.spring_jwt_toolkit.exception.JwtConfigurationException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.springframework.util.ReflectionUtils;

class JwtModelMetadata {

  private final Class<?> modelClass;
  private final Constructor<?> constructor;
  private final Map<TokenType, Field> subjectFields = new EnumMap<>(TokenType.class);
  private final Map<TokenType, List<JwtClaimFieldMetadata>> claimFields = new EnumMap<>(TokenType.class);

  JwtModelMetadata(Class<?> modelClass) {
    this.modelClass = modelClass;
    if (!modelClass.isAnnotationPresent(JwtModel.class)) {
      throw new JwtConfigurationException(
          "Class %s is not annotated with @JwtModel".formatted(modelClass.getName()));
    }

    try {
      this.constructor = modelClass.getDeclaredConstructor();
      ReflectionUtils.makeAccessible(this.constructor);
    } catch (NoSuchMethodException ex) {
      throw new JwtConfigurationException(
          "Class %s must declare a no-args constructor".formatted(modelClass.getName()));
    }

    ReflectionUtils.doWithFields(
        modelClass,
        this::registerField,
        field ->
            field.isAnnotationPresent(JwtSubject.class)
                || field.isAnnotationPresent(JwtClaim.class));
  }

  private void registerField(Field field) {
    ReflectionUtils.makeAccessible(field);
    if (field.isAnnotationPresent(JwtSubject.class)) {
      registerSubjectField(field);
    }
    if (field.isAnnotationPresent(JwtClaim.class)) {
      registerClaimField(field);
    }
  }

  private void registerSubjectField(Field field) {
    JwtSubject annotation = field.getAnnotation(JwtSubject.class);
    TokenType[] tokenTypes = annotation.tokenTypes();
    for (TokenType tokenType : tokenTypes) {
      Field existing = subjectFields.get(tokenType);
      if (existing != null && existing != field) {
        throw new JwtConfigurationException(
            "Multiple subject fields found for %s on %s"
                .formatted(tokenType, modelClass.getName()));
      }
      subjectFields.put(tokenType, field);
    }
  }

  private void registerClaimField(Field field) {
    JwtClaim annotation = field.getAnnotation(JwtClaim.class);
    for (TokenType tokenType : annotation.tokenTypes()) {
      claimFields
          .computeIfAbsent(tokenType, key -> new ArrayList<>())
          .add(new JwtClaimFieldMetadata(annotation.name(), field));
    }
  }

  Field getSubjectField(TokenType tokenType) {
    return subjectFields.get(tokenType);
  }

  List<JwtClaimFieldMetadata> getClaimFields(TokenType tokenType) {
    return claimFields.getOrDefault(tokenType, List.of());
  }

  Object createInstance() {
    try {
      return constructor.newInstance();
    } catch (Exception ex) {
      throw new JwtConfigurationException(
          "Failed to create instance of %s: %s"
              .formatted(modelClass.getName(), ex.getMessage()));
    }
  }

  Class<?> getModelClass() {
    return modelClass;
  }
}
