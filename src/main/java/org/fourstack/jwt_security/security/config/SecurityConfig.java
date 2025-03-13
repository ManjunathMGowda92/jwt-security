package org.fourstack.jwt_security.security.config;

import lombok.RequiredArgsConstructor;
import org.fourstack.jwt_security.security.filter.CsrfCookieFilter;
import org.fourstack.jwt_security.security.filter.JwtValidationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
  private final JwtValidationFilter jwtValidationFilter;

  /**
   * Method to create Spring Security configs for the application.
   *
   * @param http HttpSecurity object.
   * @return SecurityFilterChain object.
   * @throws Exception throws Exception if any error.
   */
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
    return http
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .cors(AbstractHttpConfigurer::disable)
            .csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                    .ignoringRequestMatchers("/api/v1/user/register", "/api/v1/user/authenticate")
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .addFilterAfter(new CsrfCookieFilter(), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtValidationFilter, UsernamePasswordAuthenticationFilter.class)
            .authorizeHttpRequests(request ->
                    request.requestMatchers("/api/v1/user/register", "/api/v1/user/authenticate").permitAll()
                            .anyRequest().authenticated())
            .build();
  }

  /**
   * Method to create Bean for PasswordEncoder.
   *
   * @return PasswordEncoder object.
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }
}
