package org.fourstack.jwt_security.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.fourstack.jwt_security.exception.ErrorDetails;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {
  private HttpStatus status;
  private String jwtToken;
  private LocalDateTime creationTime;
  private ErrorDetails errorDetails;
}
