package org.fourstack.jwt_security.controller;

import lombok.RequiredArgsConstructor;
import org.fourstack.jwt_security.model.AuthenticationRequest;
import org.fourstack.jwt_security.model.AuthenticationResponse;
import org.fourstack.jwt_security.model.UserRegistrationDetails;
import org.fourstack.jwt_security.service.AdminUserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller class to handle the user related operations.
 */
@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
public class UserController {
  private final AdminUserService userService;

  /**
   * Method to register the user to the database. Method throws the exception if user already exists
   * with the email ID.
   *
   * @param details UserRegistrationDetails object.
   * @return ResponseEntity with message as user registered successful.
   */
  @PostMapping("/register")
  public ResponseEntity<String> registerUser(@RequestBody UserRegistrationDetails details) {
    userService.createUser(details);
    return ResponseEntity.ok("User Registered successfully");
  }

  /**
   * Method to get AuthenticationResponse object by validating the AuthenticationRequest object with
   * email and password.
   *
   * @param request AuthenticationRequest object.
   * @return ResponseEntity with AuthenticationResponse object.
   * AuthenticationResponse will have JWT token or ErrorDetails.
   */
  @PostMapping("/authenticate")
  public ResponseEntity<AuthenticationResponse> getAuthenticationDetails(@RequestBody AuthenticationRequest request) {
    return ResponseEntity.ok(userService.createAuthToken(request));
  }
}
