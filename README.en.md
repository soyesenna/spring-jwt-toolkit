# Spring JWT Toolkit

A lightweight Spring Boot companion library that makes generating and validating signed JSON Web Tokens effortless.  
Whether you are building a stateless API gateway or a monolithic web app, the toolkit keeps token orchestration declarative, type-safe, and testable.

---

## ✨ Features

- **Annotation-driven models** – annotate your domain objects with `@JwtModel`, `@JwtSubject`, and `@JwtClaim` to describe how fields map to JWT subjects and claims.
- **Pluggable token lifecycle** – configure signing keys, validity windows, and security policies for access and refresh tokens independently.
- **Optional JPA entity lookup** – enable `jwt.use-jpa=true` to let `JwtToolKit` automatically load entities by their `@Id` fields (supports both `jakarta` and `javax` namespaces).
- **Spring Boot auto-configuration** – drop the dependency and start injecting the one-stop `JwtToolKit` bean immediately.
- **ObjectMapper management** – ships with a Jackson instance that auto-discovers modules, so Java Time and other modern types just work.
- **Test-friendly design** – simple APIs, no static singletons, and in-memory stubs included for unit testing.
- **Fine-grained error reporting** – expired tokens raise `JwtExpiredException`, while malformed ones trigger `JwtInvalidException`.
- **Request context snapshot** – headers, cookies, and JSON bodies are cached per request and surfaced through `JwtToolKit` helpers backed by `HttpRequestContextHolder`.

---

## 🚀 Quick Start

```groovy
dependencies {
    implementation 'com.soyesenna:spring-jwt-toolkit:0.0.1'
}
```

### 1. Describe a JWT model

```java
@JwtModel
public class AccountToken {

  @JwtSubject(tokenTypes = TokenType.ACCESS)
  private Long userId;

  @JwtClaim(name = "roles")
  private List<String> roles;

  // getters/setters (or Lombok)
}
```

### 2. Configure your tokens

```yaml
jwt:
  access:
    key: ${JWT_ACCESS_KEY}
    validity: PT15M
  refresh:
    key: ${JWT_REFRESH_KEY}
    validity: P7D
  use-jpa: true
```

### 3. Inject and use the beans

```java
@RestController
@RequiredArgsConstructor
class AuthController {
  private final JwtToolKit jwtToolKit;

  @PostMapping("/tokens")
  public Map<TokenType, JwtToken> issue(@RequestBody AccountToken token) {
    return this.jwtToolKit.generateTokens(token);
  }

  @GetMapping("/me")
  public AccountToken me(@RequestHeader("Authorization") String bearer) {
    String token = bearer.substring("Bearer ".length());
    return this.jwtToolKit.extract(token, TokenType.ACCESS, AccountToken.class).body();
  }
}
```

### 4. Spring Security integration

Call `jwtToolKit.extract(...)` inside your authentication filter or provider to turn compact JWTs into strongly typed principals before wrapping them in your own `Authentication` implementation.

### 5. Request context helpers

The toolkit automatically registers a servlet filter that caches headers, cookies, and JSON bodies in a thread-local context:

```java
String tenantId = HttpRequestContextHolder.getContext()
    .map(ctx -> ctx.headers().get("X-Tenant-Id"))
    .orElse(null);

JwtExtractionResult<AccountToken> session =
    jwtToolKit.extractAccessTokenFromCookie("SESSION", AccountToken.class)
        .orElseThrow();
AccountToken principal =
    jwtToolKit.extractAccessTokenFromAuthorizationBearer(AccountToken.class)
        .map(JwtExtractionResult::body)
        .orElse(null);
```

---

## ⚙️ Configuration Reference

| Property | Description | Default |
| --- | --- | --- |
| `jwt.access.key` | HMAC key used for access tokens (plain text or Base64). | _required_ |
| `jwt.access.validity` | Validity of access tokens (`Duration`). | `PT0S` (invalid without override) |
| `jwt.refresh.key` | HMAC key used for refresh tokens. | _required_ |
| `jwt.refresh.validity` | Validity of refresh tokens (`Duration`). | `PT0S` |
| `jwt.use-jpa` | Enables entity lookup via `EntityManager` using `@Id`. | `false` |

---

## ⚠️ Error Handling

| Exception | When it happens |
| --- | --- |
| `JwtExpiredException` | Token signature is valid but the `exp` claim is in the past. |
| `JwtInvalidException` | Signature/structure is invalid or verification fails for other reasons. |
| `JwtProcessingException` | Generic processing error (e.g., null subject during generation). |

When `jwt.use-jpa=true`, the toolkit:

1. Searches for either `jakarta.persistence.EntityManager` or `javax.persistence.EntityManager`.
2. Finds the first `@Id` field in the model hierarchy.
3. Uses the ID value to fetch the entity from JPA and returns it as the extraction result.

---

## 🛠️ Building & Testing

```bash
./gradlew clean build
./gradlew test
```

> The project targets Java 21 and Spring Boot 3.5.x.  
> Gradle Wrapper downloads dependencies on first run; set `JAVA_HOME` accordingly.

---

## 📚 Project Structure

```
src/main/java
├─ annotations/    # JwtModel, JwtSubject, JwtClaim
├─ configuration/  # auto-configuration & properties
├─ process/        # toolkit core, metadata, token settings
└─ exception/      # toolkit-specific exception hierarchy
```

Unit tests live under `src/test/java` and include lightweight JPA stubs to validate entity lookup without a persistence provider.

---

## 🤝 Contributing

1. Fork the repository & create a topic branch.
2. Write tests and keep the coverage meaningful.
3. Run `./gradlew test` before opening a pull request.
4. Describe your change clearly—bonus points for updating docs.

Bug reports and feature suggestions are welcome via GitHub Issues!

---

## 📄 License

Distributed under the MIT License.  
See [`LICENSE`](LICENSE) for details.
