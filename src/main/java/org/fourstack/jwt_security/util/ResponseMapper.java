package org.fourstack.jwt_security.util;

import org.fourstack.jwt_security.exception.ErrorDetails;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

public class ResponseMapper {
  public static ErrorDetails buildErrorResponse(String errorCode, String errorMessage, String path, HttpStatus status) {
    return ErrorDetails.builder()
            .errorCode(errorCode)
            .errorMessage(errorMessage)
            .path(path)
            .status(status)
            .statusCode(status.value())
            .timeStamp(LocalDateTime.now())
            .build();
  }
}
