# Spring JWT Toolkit

[English](README.en.md)

JWT 생성과 검증을 간결하게 만들어 주는 Spring Boot 전용 라이브러리입니다.  
도메인 모델에 어노테이션만 붙이면, 토큰 생성/파싱 로직을 일관되고 테스트 가능한 방식으로 구성할 수 있습니다.

---

## ✨ 주요 기능

- **어노테이션 기반 모델링** – `@JwtModel`, `@JwtSubject`, `@JwtClaim`만으로 JWT와 도메인 객체 간 매핑 정의.
- **유연한 토큰 라이프사이클** – 액세스/리프레시 토큰마다 키와 유효 기간을 독립적으로 설정.
- **선택적 JPA 연동** – `jwt.use-jpa=true`면 `@Id` 필드를 이용해 `JwtToolKit`이 엔티티를 자동 조회.
- **Spring Boot 자동 구성** – 의존성만 추가하면 원스톱 `JwtToolKit` 빈을 바로 주입 가능.
- **ObjectMapper 자동 관리** – 모듈 자동 탐색으로 Java Time 등을 별도 설정 없이 처리.
- **테스트 친화적 구조** – 간단한 API, stubs 제공, 정적 의존성 없음.
- **구체적인 예외 구분** – 만료 토큰(`JwtExpiredException`)과 잘못된 토큰(`JwtInvalidException`)을 별도 예외로 구분.

---

## 🚀 빠른 시작

```groovy
dependencies {
    implementation 'com.soyesenna:spring-jwt-toolkit:0.0.1'
}
```

### 1. JWT 모델 정의

```java
@JwtModel
public class AccountToken {

  @JwtSubject(tokenTypes = TokenType.ACCESS)
  private Long userId;

  @JwtClaim(name = "roles")
  private List<String> roles;
}
```

### 2. 설정 추가

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

### 3. 빈 사용 예시

```java
@RestController
@RequiredArgsConstructor
class AuthController {
  private final JwtToolKit jwtToolKit;

  @PostMapping("/tokens")
  Map<TokenType, JwtToken> issue(@RequestBody AccountToken token) {
    return this.jwtToolKit.generateTokens(token);
  }

  @GetMapping("/me")
  AccountToken me(@RequestHeader("Authorization") String bearer) {
    String token = bearer.substring("Bearer ".length());
    return this.jwtToolKit.extract(token, TokenType.ACCESS, AccountToken.class).body();
  }
}
```

### 4. Spring Security 통합

필터나 `AuthenticationProvider` 내부에서 `jwtToolKit.extract(...)`를 호출해 JWT를 파싱한 뒤,  
원하는 형태의 `Authentication` 구현체로 감싸서 보안 컨텍스트에 저장하면 됩니다.

---

## ⚙️ 설정 요약

| 프로퍼티 | 설명 | 기본값 |
| --- | --- | --- |
| `jwt.access.key` | 액세스 토큰 서명 키 (평문 또는 Base64). | 필수 |
| `jwt.access.validity` | 액세스 토큰 유효 시간 (`Duration`). | `PT0S` |
| `jwt.refresh.key` | 리프레시 토큰 서명 키. | 필수 |
| `jwt.refresh.validity` | 리프레시 토큰 유효 시간. | `PT0S` |
| `jwt.use-jpa` | `EntityManager`를 통한 엔티티 조회 활성화. | `false` |

---

## ⚠️ 에러 처리

| 예외 | 발생 시점 |
| --- | --- |
| `JwtExpiredException` | 서명은 유효하지만 `exp` 클레임이 현재 시각보다 과거인 경우 |
| `JwtInvalidException` | 서명 검증 실패, 구조가 잘못된 JWT 등 |
| `JwtProcessingException` | 토큰 생성 시 subject가 null 등 기타 처리 오류 |

`jwt.use-jpa=true`일 때 수행되는 단계:

1. `jakarta`/`javax` `EntityManager` 중 사용 가능한 타입 탐색.
2. 모델(또는 슈퍼클래스)의 첫 번째 `@Id` 필드 찾기.
3. 해당 ID로 JPA에서 엔티티 조회 후 결과 반환.

---

## 🛠️ 빌드 & 테스트

```bash
./gradlew clean build
./gradlew test
```

- Java 21, Spring Boot 3.5.x 기준.
- Gradle Wrapper 사용 시 최초 실행에서 의존성 다운로드가 발생합니다.

---

## 📚 프로젝트 구조

```
src/main/java
├─ annotations/    # JWT 모델 어노테이션
├─ configuration/  # Auto Configuration / Properties
├─ process/        # Toolkit 핵심 로직과 Metadata
└─ exception/      # 예외 계층
```

테스트용 JPA 스텁은 `src/test/java`에 포함되어 있으며, 실제 퍼시스턴스 없이도 JPA 연동 로직을 검증합니다.

---

## 🤝 기여 방법

1. 저장소를 포크하고 브랜치를 만듭니다.
2. 관련 테스트를 작성합니다.
3. `./gradlew test`가 성공하는지 확인합니다.
4. 변경 사항과 사용법을 README나 주석에 반영하면 더욱 좋습니다.

이슈/PR 모두 환영합니다!

---

## 📄 라이선스

본 프로젝트는 MIT License를 따릅니다.  
자세한 내용은 [`LICENSE`](LICENSE)를 참조하세요.
