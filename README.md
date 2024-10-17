## 1. 학습 목적
이번 학습의 목적은 **Spring Boot, JWT**를 활용하여 로그인 서비스를 만들려고 한다. <br>
Spring Security에 대한 부분도 있지만 해당 부분은 이번 학습목적에 주된 내용이 아니기에 많은 설명을 하지는 않을것이다.

## 2. Security 기본 설정
JWT 적용하기 위해서는 Spring Security를 적용하는것은 필수 적이다.
그래야 로그인이 되지 않는 사용자에게 서비스를 제공하지 않을 수 있기 때문이다. <br>
Spring Security를 적용하기 위해서는 gradle에 해당 라이브러를 추가해 주면 된다.

```groovy
implementation 'org.springframework.boot:spring-boot-starter-security'
```

추가하였다고 해도 Security가 제대로 작동하기 위해서는 추가적으로 해야 할 것이 있다.

```java
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .anyRequest().authenticated();
    }

}
```
@EnableWebSecurity 는 기본적인 Web 보안을 활성화 하겠다는 어노테이션이고, 추가적인 설정을 위해서 WebSecurityConfigurer을 implements하거나 WebSecurityConfigurerAdapter를 extends하는 방법이 있다. <br> 
여기서는 WebSecurityConfigurerAdapter을 extends하여 설정을 진행했다. <br>
configure 메소드를 오버라이드하여 /api/hello에 대한 접근이 인증없이 접근될 수 있도록 허용한다. <br>
authorizeRequests()는 HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정하겠다는 의미이고, antMatchers(path).permitAll() 는 해당 path로 들어오는 요청은 인증없이 접근을 허용하겠다는 의미 이다. <br>
.anyRequest().authenticated()는 나머지 요청은 모두 인증되어야 한다는 의미이다.

## 3. Application.yml 설정

```yaml
spring:
  h2:
    console:
      enabled: true

  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password:

  jpa:
    database-platform: org.hibernate.dialect.H2Dialect
    hibernate:
      ddl-auto: create-drop
    properties:
      hibernate:
        format_sql: true
        show_sql: true
    defer-datasource-initialization: true

jwt:
  header: Authorization
  secret: c2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQtc2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQK
  token-validity-in-seconds: 86400
```
나는 h2 Database를 사용할 것이고, Memory 상에 데이터를 저장하는 방식으로 진행할 것 이다.
h2 console을 true로 설정하고 datasource에 대한 설정을 해준다.
jpa관련 기본 설정 및 Console 창에서 실행되는 sql을 보기위한 설정도 추가하겠다.
create-drop의 의미는 SessionFactory가 시작될 때 Drop, Create, Alter를 하고, 종료될때 Drop을 진행한다는 의미이다.

HS512 알고리즘을 사용할 것이기 때문에 secret key는 512bit, 즉 64byte 이상을 사용해야 한다.
터미널에서 secret key를 base64로 인코딩하여 secret 항목에 채워넣는다.

참고로 h2 Database를 사용하기 위해서는 아래 코드를 gradle에 추가하면 된다.
```groovy
runtimeOnly 'com.h2database:h2'
```

## 4. Entity 생성

```java
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import javax.persistence.*;
import java.util.Set;

@Entity
@Table(name = "user")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User {

   @JsonIgnore
   @Id
   @Column(name = "user_id")
   @GeneratedValue(strategy = GenerationType.IDENTITY)
   private Long userId;

   @Column(name = "username", length = 50, unique = true)
   private String username;

   @JsonIgnore
   @Column(name = "password", length = 100)
   private String password;

   @Column(name = "nickname", length = 50)
   private String nickname;

   @JsonIgnore
   @Column(name = "activated")
   private boolean activated;

   @ManyToMany
   @JoinTable(
      name = "user_authority",
      joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "user_id")},
      inverseJoinColumns = {@JoinColumn(name = "authority_name", referencedColumnName = "authority_name")})
   private Set<Authority> authorities;
}
```

```java
import lombok.*;
import javax.persistence.*;

@Entity
@Table(name = "authority")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Authority {

   @Id
   @Column(name = "authority_name", length = 50)
   private String authorityName;
}
```
User, Authority Entity를 추가해보자

@Entity는 Database Table과 1:1로 매핑되는 객체를 뜻한다. <br>
@Table은 객체와 매핑되는 Database의 Table명을 지정하기 위해 사용한다. <br>
@Getter, @Setter, @builder, @AllArgsConstructor, @NoArgsConstructor 는 Lombok Annotation으로 Get, Set, Builder, Constructor 관련 코드를 자동으로 생성한다. <br>
@JsonIgnore는 서버에서 Json 응답을 생성할때 해당 필드는 ignore 하겠다는 의미이다. <br>
@Id는 해당 필드가 Primary Key임을 의미하고 @Column은 매핑되는 Database Column의 정보를 정의한다. <br>
@ManyToMany @JoinTable 부분은 쉽게 말해 User, Authority 테이블의 다대다 관계를 일대다, 다대일 관계의 조인 테이블로 정의한다.

Spring Boot 서버가 시작될때 마다 Table들이 새로 Create되기 때문에 편의를 위해 초기 데이터를 자동으로 Database에 넣어주는 기능이다. <br>
/src/main/resources 하위에 data.sql 파일을 만들어보자.

```sql
INSERT INTO USER (USER_ID, USERNAME, PASSWORD, NICKNAME, ACTIVATED) VALUES (1, 'admin', '$2a$08$lDnHPz7eUkSi6ao14Twuau08mzhWrL4kyZGGU5xfiGALO/Vxd5DOi', 'admin', 1);

INSERT INTO AUTHORITY (AUTHORITY_NAME) values ('ROLE_USER');
INSERT INTO AUTHORITY (AUTHORITY_NAME) values ('ROLE_ADMIN');

INSERT INTO USER_AUTHORITY (USER_ID, AUTHORITY_NAME) values (1, 'ROLE_USER');
INSERT INTO USER_AUTHORITY (USER_ID, AUTHORITY_NAME) values (1, 'ROLE_ADMIN');
```

## 5. JWT 설정 추가

이후에 Security 설정에 h2-console를 사용할 수 있도록 설정을 추가하자.

```java
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web) {
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**"
                        ,"/favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .anyRequest().authenticated();
    }

}
```

h2-console 페이지의 접근은 Spring Security 관련 로직을 수행하지 않도록 configure를 오버라이드한 메소드를 새롭게 추가한다.

이후 build.gradle에 아래 설정을 추가해 주자.

```groovy
compile group: 'io.jsonwebtoken', name: 'jjwt-api', version: '0.11.2'
runtime group: 'io.jsonwebtoken', name: 'jjwt-impl', version: '0.11.2'
runtime group: 'io.jsonwebtoken', name: 'jjwt-jackson', version: '0.11.2'
```

### TokenProvider.java

jwt 패키지를 생성한 후 TokenProvider.java 파일을 생성합니다.

```java
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {

   private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

   private static final String AUTHORITIES_KEY = "auth";

   private final String secret;
   private final long tokenValidityInMilliseconds;

   private Key key;


   public TokenProvider(
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
      this.secret = secret;
      this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
   }

   @Override
   public void afterPropertiesSet() {
      byte[] keyBytes = Decoders.BASE64.decode(secret);
      this.key = Keys.hmacShaKeyFor(keyBytes);
   }

   public String createToken(Authentication authentication) {
      String authorities = authentication.getAuthorities().stream()
         .map(GrantedAuthority::getAuthority)
         .collect(Collectors.joining(","));

      long now = (new Date()).getTime();
      Date validity = new Date(now + this.tokenValidityInMilliseconds);

      return Jwts.builder()
         .setSubject(authentication.getName())
         .claim(AUTHORITIES_KEY, authorities)
         .signWith(key, SignatureAlgorithm.HS512)
         .setExpiration(validity)
         .compact();
   }

   public Authentication getAuthentication(String token) {
      Claims claims = Jwts
              .parserBuilder()
              .setSigningKey(key)
              .build()
              .parseClaimsJws(token)
              .getBody();

      Collection<? extends GrantedAuthority> authorities =
         Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

      User principal = new User(claims.getSubject(), "", authorities);

      return new UsernamePasswordAuthenticationToken(principal, token, authorities);
   }

   public boolean validateToken(String token) {
      try {
         Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
         return true;
      } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
         logger.info("잘못된 JWT 서명입니다.");
      } catch (ExpiredJwtException e) {
         logger.info("만료된 JWT 토큰입니다.");
      } catch (UnsupportedJwtException e) {
         logger.info("지원되지 않는 JWT 토큰입니다.");
      } catch (IllegalArgumentException e) {
         logger.info("JWT 토큰이 잘못되었습니다.");
      }
      return false;
   }
}
```
TokenProvider 빈은 application.yml에서 정의한 jwt.secret, jwt.token-validity-in-seconds 값을 주입받도록 한다. <br>
InitializingBean을 구현하고 afterPropertiesSet()을 오버라이드한 이유는 빈이 생성되고 의존성 주입까지 끝낸 이후에 주입받은 secret 값을 base64 decode하여 key 변수에 할당하기 위해서다. <br>
**createToken** 메소드는 Authentication 객체에 포함되어 있는 권한 정보들을 담은 토큰을 생성하고
jwt.token-validity-in-seconds 값을 이용해 토큰의 만료 시간을 지정한다. <br>
**getAuthentication** 메소드는 토큰에 담겨있는 권한 정보들을 이용해 Authentication 객체를 리턴한다.
**validateToken** 메소드는 토큰을 검증하는 역할을 수행한다.

### JwtFilter.java

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class JwtFilter extends GenericFilterBean {

   private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

   public static final String AUTHORIZATION_HEADER = "Authorization";

   private TokenProvider tokenProvider;

   public JwtFilter(TokenProvider tokenProvider) {
      this.tokenProvider = tokenProvider;
   }

   @Override
   public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {
      HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
      String jwt = resolveToken(httpServletRequest);
      String requestURI = httpServletRequest.getRequestURI();

      if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
         Authentication authentication = tokenProvider.getAuthentication(jwt);
         SecurityContextHolder.getContext().setAuthentication(authentication);
         logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
      } else {
         logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
      }

      filterChain.doFilter(servletRequest, servletResponse);
   }

   private String resolveToken(HttpServletRequest request) {
      String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
      if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
         return bearerToken.substring(7);
      }
      return null;
   }
}
```

JWT를 위한 Custom Filter를 만들기 위해 GenericFilterBean을 extends한 JwtFilter.java를 생성한다.
JwtFilter빈은 TokenProvider를 주입받는다.
실제 필터링 로직은 **doFilter** 메소드를 오버라이드하여 작성한다.
**resolveToken** 메소드는 HttpServletRequest 객체의 Header에서 token을 꺼내는 역할을 수행한다.
**doFilter** 메소드는 jwt 토큰의 인증 정보를 현재 실행중인 스레드 ( Security Context ) 에 저장한다.

### JwtSecurityConfig.java

```java
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private TokenProvider tokenProvider;

    public JwtSecurityConfig(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void configure(HttpSecurity http) {
        JwtFilter customFilter = new JwtFilter(tokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
```

JwtSecurityConfig.java 는 SecurityConfigurerAdapter를 extends하며 configure메소드를 오버라이드하여 위에서 만든 JwtFilter를 Security 로직에 적용하는 역할을 수행한다.

### JwtAuthenticationEntryPoint.java

```java
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

   @Override
   public void commence(HttpServletRequest request,
                        HttpServletResponse response,
                        AuthenticationException authException) throws IOException {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
   }
}
```

유효한 자격증명을 제공하지 않고 접근하려 할때 401 UNAUTHORIZED 에러를 리턴하기 위해 AuthenticationEntryPoint를 구현한 JwtAuthenticationEntryPoint 클래스를 작성한다.

### JwtAccessDeniedHandler.java

```java
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

   @Override
   public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
   }
}
```

필요한 권한이 존재하지 않은 경우 403 FORBIDDEN 에러를 리턴하기 위해 AccessDeniedHandler를 구현한 JwtAccessDeniedHandler 클래스를 작성한다.

### Security 설정 추가

```java
import me.silvernine.tutorial.jwt.JwtAccessDeniedHandler;
import me.silvernine.tutorial.jwt.JwtAuthenticationEntryPoint;
import me.silvernine.tutorial.jwt.JwtSecurityConfig;
import me.silvernine.tutorial.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**"
                        , "/favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()
                .anyRequest().authenticated()

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
    }

}
```

@EnableGlobalMethodSecurity(prePostEnabled = true) 어노테이션은 메소드 단위로 @PreAuthorize 검증 어노테이션을 사용하기 위해 추가한다.
위에서 만들었던 TokenProvider, JwtAuthenticationEntryPoint, JwtAccessDeniedHandler를 주입받는 코드를 추가한다.
Password Encode는 BCryptPasswordEncoder()를 사용한다.

```java
.csrf().disable()
```

우리는 Token 방식을 사용하므로 csrf 설정을 disable 한다.

```java
.exceptionHandling()
.authenticationEntryPoint(jwtAuthenticationEntryPoint)
.accessDeniedHandler(jwtAccessDeniedHandler)
```

예외처리를 위해 만들었던 코드를 지정해주자.

```java
.and()
.headers()
.frameOptions()
.sameOrigin()
```

데이터 확인을 위해 사용하고 있는 h2-console을 위한 설정을 추가하자.

```java
.and()
.sessionManagement()
.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
```

우리는 세션을 사용하지 않기 때문에 세션 설정을 STATELESS로 지정해준다.

```java
.and()
.authorizeRequests()
.antMatchers("/api/hello").permitAll()
.antMatchers("/api/authenticate").permitAll()
.antMatchers("/api/signup").permitAll()
.anyRequest().authenticated()
```

/api/hello, /api/authenticate, /api/signup 3가지 API는 Token이 없어도 호출할 수 있도록 허용한다.

```java
.and()
.apply(new JwtSecurityConfig(tokenProvider));
```

위에서 만들었던 JwtFilter를 addFilterBefore 메소드로 등록했던 JwtSecurityConfig 클래스도 적용해준다.

## 6. Repository, 로그인

dto 패키지를 만들고 외부와의 데이터 통신에 사용할 3개의 클래스를 만들어 주자.

```java
import lombok.*;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginDto {

   @NotNull
   @Size(min = 3, max = 50)
   private String username;

   @NotNull
   @Size(min = 3, max = 100)
   private String password;
}
```

```java
import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenDto {
    private String token;
}
```

```java
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {

   @NotNull
   @Size(min = 3, max = 50)
   private String username;

   @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
   @NotNull
   @Size(min = 3, max = 100)
   private String password;

   @NotNull
   @Size(min = 3, max = 50)
   private String nickname;
}
```

### 로그인

```java
import me.silvernine.tutorial.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
   @EntityGraph(attributePaths = "authorities")
   Optional<User> findOneWithAuthoritiesByUsername(String username);
}
```

이전에 만들었던 User Entity에 매핑되는 Repository를 만들기 위해 repository 패키지를 생성하고 UserRepository 인터페이스를 추가한다.
JpaRepository를 extends하는 것으로 save(), findOne(), findAll() 등의 메소드를 기본적으로 사용할 수 있게 된다.
**findOneWithAuthoritiesByUsername** 메소드는 username을 기준으로 User 정보 ( authorities 정보 포함 ) 를 가져오는 역할을 수행한다. 
@EntityGraph(attributePaths) 어노테이션은 해당 쿼리가 수행될때 Lazy 조회가 아닌 Eager 조회로 authorities 정보를 조인해서 가져오게 된다.

### CustomUserDetailsService.java

```java
import me.silvernine.tutorial.entity.User;
import me.silvernine.tutorial.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Component("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {
   private final UserRepository userRepository;

   public CustomUserDetailsService(UserRepository userRepository) {
      this.userRepository = userRepository;
   }

   @Override
   @Transactional
   public UserDetails loadUserByUsername(final String username) {
      return userRepository.findOneWithAuthoritiesByUsername(username)
         .map(user -> createUser(username, user))
         .orElseThrow(() -> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));
   }

   private org.springframework.security.core.userdetails.User createUser(String username, User user) {
      if (!user.isActivated()) {
         throw new RuntimeException(username + " -> 활성화되어 있지 않습니다.");
      }
      List<GrantedAuthority> grantedAuthorities = user.getAuthorities().stream()
              .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
              .collect(Collectors.toList());
      return new org.springframework.security.core.userdetails.User(user.getUsername(),
              user.getPassword(),
              grantedAuthorities);
   }
}
```

UserDetailsService를 implements하고 위에서 만들었던 UserRepository를 주입받는 CustomUserDetailsService 클래스를 생성한다.
로그인 시 **authenticate** 메소드를 수행할때 Database에서 User 정보를 조회해오는 **loadUserByUsername** 메소드가 실행된다.

```java
return userRepository.findOneWithAuthoritiesByUsername(username)
   .map(user -> createUser(username, user))
   .orElseThrow(() -> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));
```

우리는 **loadUserByUsername** 메소드를 오버라이드해서 Database에서 User 정보를 권한 정보와 함께 가져오는 로직을 구현했다.
람다식을 이용해 Database에서 조회해온 User 및 권한 정보를 org.springframework.security.core.userdetails.User 객체로 변환하여 리턴한다.

### AuthController.java

```java
import me.silvernine.tutorial.dto.LoginDto;
import me.silvernine.tutorial.dto.TokenDto;
import me.silvernine.tutorial.jwt.JwtFilter;
import me.silvernine.tutorial.jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = tokenProvider.createToken(authentication);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}
```

TokenProvider, AuthenticationManagerBuilder 를 주입받는 AuthController 클래스를 만들겠다. <br>
/api/authenticate 요청을 처리하는 **authorize** 메소드는 username, password를 파라미터로 받아서 UsernamePasswordAuthenticationToken 객체를 생성한다. <br>
해당 객체를 통해 **authenticate** 메소드 로직을 수행한다. 이때 위에서 만들었던 **loadUserByUsername** 메소드가 수행되며 유저 정보를 조회해서 인증 정보를 생성하게 된다. <br>
해당 인증 정보를 JwtFilter 클래스의 **doFilter** 메소드와 유사하게 현재 실행중인 스레드 ( Security Context ) 에 저장한다. <br>
또한 해당 인증 정보를 기반으로 TokenProvider의 **createToken** 메소드를 통해 jwt 토큰을 생성한다. <br>
생성된 Token을 Response Header에 넣고, TokenDto 객체를 이용해 Reponse Body에도 넣어서 리턴한다.

## 7. 회원가입

### SecurityUtil.java

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public class SecurityUtil {

   private static final Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

   private SecurityUtil() {
   }

   public static Optional<String> getCurrentUsername() {
      final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

      if (authentication == null) {
         logger.debug("Security Context에 인증 정보가 없습니다.");
         return Optional.empty();
      }

      String username = null;
      if (authentication.getPrincipal() instanceof UserDetails) {
         UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
         username = springSecurityUser.getUsername();
      } else if (authentication.getPrincipal() instanceof String) {
         username = (String) authentication.getPrincipal();
      }

      return Optional.ofNullable(username);
   }
}
```

util 패키지를 생성한 후 SecurityUtil 클래스를 생성한다.
**getCurrentUsername()** 메소드는 JwtFilter 클래스의 doFilter 메소드에서 저장한 Security Context의 인증 정보에서 username을 리턴한다.

### UserService.java

```java
import me.silvernine.tutorial.dto.UserDto;
import me.silvernine.tutorial.entity.Authority;
import me.silvernine.tutorial.entity.User;
import me.silvernine.tutorial.repository.UserRepository;
import me.silvernine.tutorial.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}
```

UserRepository, PasswordEncoder를 주입받는 UserService 클래스를 생성한다.
**signup** 메소드는 이미 같은 username으로 가입된 유저가 있는 지 확인하고, UserDto 객체의 정보들을 기반으로 권한 객체와 유저 객체를 생성하여 Database에 저장한다.
**getUserWithAuthorities** 메소드는 username을 파라미터로 받아 해당 유저의 정보 및 권한 정보를 리턴한다.
**getMyUserWithAuthorities** 메소드는 위에서 만든 SecurityUtil의 **getCurrentUsername()** 메소드가 리턴하는 username의 유저 및 권한 정보를 리턴한다.

### UserController.java

```java
import me.silvernine.tutorial.dto.UserDto;
import me.silvernine.tutorial.entity.User;
import me.silvernine.tutorial.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<User> signup(
            @Valid @RequestBody UserDto userDto
    ) {
        return ResponseEntity.ok(userService.signup(userDto));
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<User> getMyUserInfo() {
        return ResponseEntity.ok(userService.getMyUserWithAuthorities().get());
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<User> getUserInfo(@PathVariable String username) {
        return ResponseEntity.ok(userService.getUserWithAuthorities(username).get());
    }
}
```

controller 패키지에 UserService를 주입받는 UserController 클래스를 생성한다. <br>
**signup** 메소드는 회원가입 API 이고 SecurityConfig.java 에서 permitAll를 설정했기 때문에 권한 없이 호출할 수 있다. <br>
**getMyUserInfo** 메소드는 현재 Security Context에 저장되어 있는 인증 정보의 username을 기준으로 한 유저 정보 및 권한 정보를 리턴하는 API다. <br>
@PreAuthorize(“hasAnyRole(‘USER’,‘ADMIN’)”) 어노테이션을 이용해서 ROLE_USER, ROLE_ADMIN 권한 모두 호출 가능하게 설정한다. <br>
**getUserInfo** 메소드는 username을 파라미터로 받아 해당 username의 유저 정보 및 권한 정보를 리턴한다. <br>
@PreAuthorize(“hasAnyRole(‘ADMIN’)”) 어노테이션을 이용해서 ROLE_ADMIN 권한을 소유한 토큰만 호출할 수 있도록 설정한다.

## 8. 추가학습

지금까지 JWT를 적용하는 학습을 해보았다. 요즘은 accessToken과 refreshToken 2개의 토큰을 이용한다.
다음에는 이러한 방법에 대한 부분을 학습하면 될 것 같다.