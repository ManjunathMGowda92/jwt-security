package org.fourstack.jwt_security.model;

import lombok.Data;
import org.fourstack.jwt_security.enums.Role;

@Data
public class UserRegistrationDetails {
  private String firstName;
  private String lastName;
  private String email;
  private String pwd;
  private Role role;
}
