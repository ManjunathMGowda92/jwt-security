package org.fourstack.jwt_security.service;

import lombok.RequiredArgsConstructor;
import org.fourstack.jwt_security.constant.AppConstant;
import org.fourstack.jwt_security.entity.AppUserDetails;
import org.fourstack.jwt_security.enums.Role;
import org.fourstack.jwt_security.exception.InvalidCredentialsException;
import org.fourstack.jwt_security.exception.UserAlreadyExistException;
import org.fourstack.jwt_security.model.AuthenticationRequest;
import org.fourstack.jwt_security.model.AuthenticationResponse;
import org.fourstack.jwt_security.model.UserRegistrationDetails;
import org.fourstack.jwt_security.repository.AppUserDetailsRepository;
import org.fourstack.jwt_security.security.service.JwtTokenService;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AdminUserService {
  private final AppUserDetailsRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtTokenService jwtService;
  private final Environment environment;

  /**
   * Method to create a user in the database, by validating the user exists in database or not with email.
   *
   * @param details UserRegistrationDetails object.
   */
  public void createUser(UserRegistrationDetails details) {
    if (!isUserExist(details.getEmail())) {
      AppUserDetails user = convertToUserDetails(details);
      userRepository.save(user);
    } else {
      throw new UserAlreadyExistException("User already exists with email : " + details.getEmail());
    }
  }

  /**
   * Method to check user exist in the database or not.
   *
   * @param email Unique email ID value.
   * @return boolean value to return email exist or not.
   */
  public boolean isUserExist(String email) {
    return userRepository.existsByEmailIgnoreCase(email);
  }

  /**
   * Method to retrieve the user details from database using the email ID.
   *
   * @param email Unique email ID value.
   * @return AppUserDetails object.
   */
  public AppUserDetails retrieveUser(String email) {
    return userRepository.findByEmailIgnoreCase(email)
            .orElseThrow(() -> new UsernameNotFoundException("No user found for : " + email));
  }

  /**
   * Method to create JWT token by validating the user details.
   *
   * @param request AuthenticationRequest object with email and password.
   * @return AuthenticationResponse object with JWT token and Error Details.
   */
  public AuthenticationResponse createAuthToken(AuthenticationRequest request) {
    if (isUserExist(request.getEmail())) {
      AppUserDetails user = retrieveUser(request.getEmail());
      if (passwordEncoder.matches(request.getPassword(), user.getPassword())) {
        String secret = environment.getProperty(AppConstant.JWT_SECRET_KEY, AppConstant.DEFAULT_JWT_SECRET);
        String jwtToken = jwtService.generateToken(user, secret);
        return AuthenticationResponse.builder()
                .status(HttpStatus.OK)
                .jwtToken(jwtToken)
                .creationTime(LocalDateTime.now())
                .build();
      }
      throw new InvalidCredentialsException("Invalid password");
    } else {
      throw new UsernameNotFoundException("No user details found for :" + request.getEmail());
    }
  }

  private AppUserDetails convertToUserDetails(UserRegistrationDetails details) {
    AppUserDetails user = new AppUserDetails();
    user.setFirstName(details.getFirstName());
    user.setLastName(details.getLastName());
    user.setEmail(details.getEmail().toLowerCase());
    user.setPassword(passwordEncoder.encode(details.getPwd()));
    user.setRole(details.getRole() != null ? details.getRole() : Role.USER);
    return user;
  }
}
