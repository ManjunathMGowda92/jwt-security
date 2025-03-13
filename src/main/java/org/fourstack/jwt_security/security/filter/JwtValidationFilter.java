package org.fourstack.jwt_security.security.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.fourstack.jwt_security.constant.AppConstant;
import org.fourstack.jwt_security.security.service.JwtTokenService;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter to validate the JWT token from Authorization Header.
 */
@Component
@RequiredArgsConstructor
public class JwtValidationFilter extends OncePerRequestFilter {
  private final Environment env;
  private final JwtTokenService jwtService;
  private final UserDetailsService userDetailsService;

  /**
   * Method to verify the JWT token from the Authorization header using the secret key.
   * <p>Steps for validating the JWT token
   * <ul>
   *   <li>Fetch the authorization header value.</li>
   *   <li>Check for Auth token fetched as it starts with Bearer</li>
   *   <li>Retrieve the JWT secret key for extracting the claims using JWT token.</li>
   *   <li>Validate the username retrieved from the token with DB stored values.</li>
   *   <li>if the user is a valid one, then create Authentication object, otherwise throw an Error</li>
   * </ul>
   * </p>
   *
   * @param request     Http Servlet Request object.
   * @param response    Http Servlet Response object.
   * @param filterChain FilterChain object.
   * @throws ServletException throws ServletException if any error.
   * @throws IOException      throws IOException is any error.
   */
  @Override
  protected void doFilterInternal(@Nonnull HttpServletRequest request,
                                  @Nonnull HttpServletResponse response,
                                  @Nonnull FilterChain filterChain) throws ServletException, IOException {
    String authToken = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (authToken != null && authToken.contains("Bearer ")) {
      try {
        String jwtToken = authToken.substring(7);
        String secret = env.getProperty(AppConstant.JWT_SECRET_KEY, AppConstant.DEFAULT_JWT_SECRET);
        Claims claims = jwtService.extractClaims(jwtToken, secret);
        String username = jwtService.getUsername(claims);
        Authentication authenticationToken = validateUserAndCreateToken(username);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
      } catch (ExpiredJwtException e) {
        throw new BadCredentialsException("Token Expired!");
      } catch (UsernameNotFoundException e) {
        throw new BadCredentialsException(e.getMessage());
      } catch (Exception e) {
        throw new BadCredentialsException("Invalid Credentials!!");
      }
    }
    filterChain.doFilter(request, response);
  }

  /**
   * Method to extract the UserDetails from UserDetailsService object and return with Authentication object.
   * If user not exist, then method will throw UserNotFoundException.
   *
   * @param username NonNull valid unique email Id
   * @return AuthenticationToken Object.
   */
  private Authentication validateUserAndCreateToken(String username) {
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
    return new UsernamePasswordAuthenticationToken(username, null, userDetails.getAuthorities());
  }
}
