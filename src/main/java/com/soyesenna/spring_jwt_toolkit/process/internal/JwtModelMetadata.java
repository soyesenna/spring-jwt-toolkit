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
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

/**
 * Encapsulates all reflective metadata derived from a {@code @JwtModel}-annotated class, including
 * subject mappings, claim mappings, and optional JPA identifier fields. The metadata object is
 * intended to be cached and shared via {@link JwtModelMetadataRegistry}.
 */
public class JwtModelMetadata {

  private final Class<?> modelClass;
  private static final String[] JPA_ID_ANNOTATION_NAMES = {
      "jakarta.persistence.Id",
      "javax.persistence.Id"
  };
  private static final List<Class<? extends Annotation>> JPA_ID_ANNOTATION_CLASSES =
      resolveJpaIdAnnotations();

  private final Constructor<?> constructor;
  private final Map<TokenType, Field> subjectFields = new EnumMap<>(TokenType.class);
  private final Map<TokenType, List<JwtClaimFieldMetadata>> claimFields =
      new EnumMap<>(TokenType.class);
  private final boolean jpaEnabled;
  private final Field jpaIdField;

  /**
   * Inspects the supplied class to discover subject and claim mappings.
   *
   * @param modelClass annotated model class
   */
  public JwtModelMetadata(Class<?> modelClass) {
    this.modelClass = modelClass;
    JwtModel annotation = modelClass.getAnnotation(JwtModel.class);
    if (annotation == null) {
      throw new JwtConfigurationException(
          "Class %s is not annotated with @JwtModel".formatted(modelClass.getName())
      );
    }
    this.jpaEnabled = annotation.useJpa();

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

    this.jpaIdField = this.jpaEnabled ? resolveJpaIdField(modelClass) : null;
  }

  /**
   * @return model class that owns the metadata
   */
  public Class<?> getModelClass() {
    return modelClass;
  }

  /**
   * Registers a single field as either subject or claim metadata when applicable.
   */
  private void registerField(Field field) {
    ReflectionUtils.makeAccessible(field);
    if (field.isAnnotationPresent(JwtSubject.class)) {
      this.registerSubjectField(field);
    }
    if (field.isAnnotationPresent(JwtClaim.class)) {
      this.registerClaimField(field);
    }
  }

  /**
   * Associates a subject field with each token type declared on the {@link JwtSubject} annotation.
   */
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

  /**
   * Captures claim metadata for every token type listed on the {@link JwtClaim} annotation.
   */
  private void registerClaimField(Field field) {
    JwtClaim annotation = field.getAnnotation(JwtClaim.class);
    for (TokenType tokenType : annotation.tokenTypes()) {
      this.claimFields
          .computeIfAbsent(tokenType, key -> new ArrayList<>())
          .add(new JwtClaimFieldMetadata(annotation.name(), field));
    }
  }

  /**
   * Searches the model hierarchy for a field annotated with any supported JPA {@code @Id}.
   */
  private Field resolveJpaIdField(Class<?> type) {
    if (JPA_ID_ANNOTATION_CLASSES.isEmpty()) {
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
              && hasJpaIdAnnotation(field)) {
            ReflectionUtils.makeAccessible(field);
            holder.field = field;
          }
        });
    return holder.field;
  }

  /**
   * Resolves any available {@code @Id} annotations so the toolkit can remain compatible with both
   * Jakarta EE and older Java EE namespaces.
   */
  private static List<Class<? extends Annotation>> resolveJpaIdAnnotations() {
    List<Class<? extends Annotation>> annotations = new ArrayList<>();
    ClassLoader classLoader = JwtModelMetadata.class.getClassLoader();
    for (String className : JPA_ID_ANNOTATION_NAMES) {
      if (ClassUtils.isPresent(className, classLoader)) {
        Class<?> annotationType = ClassUtils.resolveClassName(className, classLoader);
        if (Annotation.class.isAssignableFrom(annotationType)) {
          @SuppressWarnings("unchecked")
          Class<? extends Annotation> casted = (Class<? extends Annotation>) annotationType;
          annotations.add(casted);
        }
      }
    }
    return List.copyOf(annotations);
  }

  /**
   * Determines whether the supplied field carries a supported {@code @Id} annotation.
   */
  private static boolean hasJpaIdAnnotation(Field field) {
    for (Class<? extends Annotation> annotation : JPA_ID_ANNOTATION_CLASSES) {
      if (field.getAnnotation(annotation) != null) {
        return true;
      }
    }
    return false;
  }

  /**
   * @return subject field configured for the supplied token type, or {@code null} if none exists
   */
  public Field getSubjectField(TokenType tokenType) {
    return this.subjectFields.get(tokenType);
  }

  /**
   * @return list of claim descriptors for the supplied token type
   */
  public List<JwtClaimFieldMetadata> getClaimFields(TokenType tokenType) {
    return this.claimFields.getOrDefault(tokenType, List.of());
  }

  /**
   * Creates a new instance of the model using its default constructor.
   *
   * @return zero-argument instance of the model class
   */
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

  /**
   * @return resolved JPA identifier field, or {@code null} when JPA annotations are absent
   */
  public Field getJpaIdField() {
    return this.jpaIdField;
  }

  /**
   * @return whether JPA resolution should be attempted for this model
   */
  public boolean isJpaEnabled() {
    return this.jpaEnabled;
  }
}
