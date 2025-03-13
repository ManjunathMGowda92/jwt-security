package org.fourstack.jwt_security.security.service;

import lombok.RequiredArgsConstructor;
import org.fourstack.jwt_security.repository.AppUserDetailsRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * AppUserDetailsService Class implementing the UserDetailsService, to load the user details from database.
 */
@Service
@RequiredArgsConstructor
public class AppUserDetailsService implements UserDetailsService {
  private final AppUserDetailsRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return userRepository.findByEmailIgnoreCase(username)
            .orElseThrow(() -> new UsernameNotFoundException("No user found for :" + username));
  }
}
