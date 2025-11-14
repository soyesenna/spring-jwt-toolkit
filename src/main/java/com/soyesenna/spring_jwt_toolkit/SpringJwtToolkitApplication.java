package com.soyesenna.spring_jwt_toolkit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Primary bootstrap class for the Spring JWT Toolkit sample application. The application exists
 * solely to ensure that component scanning, auto-configuration and the accompanying tests can load
 * a Spring {@link org.springframework.context.ApplicationContext}. It does not contain runtime
 * logic, but providing a runnable entry point guarantees that downstream starters can integrate this
 * library using the familiar {@code @SpringBootApplication} pattern.
 */
@SpringBootApplication
public class SpringJwtToolkitApplication {

  /**
   * Launches the Spring Boot context so integration tests can verify the starter behaves correctly
   * when pulled into a host project.
   *
   * @param args standard JVM arguments forwarded to Spring Boot
   */
  public static void main(String[] args) {
    SpringApplication.run(SpringJwtToolkitApplication.class, args);
  }
}
