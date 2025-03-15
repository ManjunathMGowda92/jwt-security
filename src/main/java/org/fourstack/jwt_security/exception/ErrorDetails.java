package org.fourstack.jwt_security.exception;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ErrorDetails {
  private String errorCode;
  private String errorMessage;
  private String path;
  private int statusCode;
  private HttpStatus status;
  private LocalDateTime timeStamp;
}
