package org.fourstack.jwt_security.security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Class implementing the AuthenticationProvider, to check the username and password matches.
 * If the user exist and password matches, then create Authentication object.
 */
@Service
@RequiredArgsConstructor
public class AppAuthenticationProvider implements AuthenticationProvider {
  private final UserDetailsService userDetailsService;
  private final PasswordEncoder passwordEncoder;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    String pwd = authentication.getCredentials().toString();
    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
    if (passwordEncoder.matches(pwd, userDetails.getPassword())) {
      return new UsernamePasswordAuthenticationToken(username, pwd, userDetails.getAuthorities());
    }
    throw new BadCredentialsException("Invalid Password!");
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
