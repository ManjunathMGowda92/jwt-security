package org.fourstack.jwt_security.exception;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import org.fourstack.jwt_security.util.ResponseMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.naming.AuthenticationException;

@ControllerAdvice
public class AppExceptionHandler {
  private static final Logger logger = LoggerFactory.getLogger(AppExceptionHandler.class);
  public static final String EXCEPTION_HANDLING_MESSAGE = "Handling Exception : {} - message : {}";

  @ExceptionHandler(AuthenticationException.class)
  public ResponseEntity<ErrorDetails> handleException(AuthenticationException exception,
                                                      HttpServletRequest request) {
    logger.error(EXCEPTION_HANDLING_MESSAGE, exception.getClass().getName(), exception.getMessage());
    ErrorDetails details = getErrorDetails("AUTHN-FAILURE-004",
            exception.getMessage(), request, HttpStatus.UNAUTHORIZED);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(details);
  }

  @ExceptionHandler(UserAlreadyExistException.class)
  public ResponseEntity<ErrorDetails> handleException(UserAlreadyExistException exception,
                                                      HttpServletRequest request) {
    logger.error(EXCEPTION_HANDLING_MESSAGE, exception.getClass().getName(), exception.getMessage());
    ErrorDetails details = getErrorDetails("AUTHN-FAILURE-001",
            exception.getMessage(), request, HttpStatus.UNAUTHORIZED);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(details);
  }

  @ExceptionHandler(UsernameNotFoundException.class)
  public ResponseEntity<ErrorDetails> handleException(UsernameNotFoundException exception,
                                                      HttpServletRequest request) {
    logger.error(EXCEPTION_HANDLING_MESSAGE, exception.getClass().getName(), exception.getMessage());
    ErrorDetails details = getErrorDetails("AUTHN-FAILURE-010",
            exception.getMessage(), request, HttpStatus.UNAUTHORIZED);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(details);
  }

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<ErrorDetails> handleException(BadCredentialsException exception,
                                                      HttpServletRequest request) {
    logger.error(EXCEPTION_HANDLING_MESSAGE, exception.getClass().getName(), exception.getMessage());
    ErrorDetails details = getErrorDetails("AUTHN-FAILURE-001",
            exception.getMessage(), request, HttpStatus.UNAUTHORIZED);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(details);
  }

  @ExceptionHandler(InvalidCredentialsException.class)
  public ResponseEntity<ErrorDetails> handleException(InvalidCredentialsException exception,
                                                      HttpServletRequest request) {
    logger.error(EXCEPTION_HANDLING_MESSAGE, exception.getClass().getName(), exception.getMessage());
    ErrorDetails details = getErrorDetails("AUTHN-FAILURE-002",
            exception.getMessage(), request, HttpStatus.UNAUTHORIZED);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(details);
  }

  @ExceptionHandler({SignatureException.class})
  public ResponseEntity<ErrorDetails> handleException(SignatureException exception,
                                                      HttpServletRequest request) {
    logger.error(EXCEPTION_HANDLING_MESSAGE, exception.getClass().getName(), exception.getMessage());
    ErrorDetails details = getErrorDetails("AUTHZ-FAILURE-001",
            "Invalid JWT Token!", request, HttpStatus.FORBIDDEN);
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(details);
  }

  @ExceptionHandler({MalformedJwtException.class})
  public ResponseEntity<ErrorDetails> handleException(MalformedJwtException exception,
                                                      HttpServletRequest request) {
    logger.error(EXCEPTION_HANDLING_MESSAGE, exception.getClass().getName(), exception.getMessage());
    ErrorDetails details = getErrorDetails("AUTHZ-FAILURE-001",
            "Invalid JWT Token!", request, HttpStatus.FORBIDDEN);
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(details);
  }

  @ExceptionHandler(ExpiredJwtException.class)
  public ResponseEntity<ErrorDetails> handleException(ExpiredJwtException exception,
                                                      HttpServletRequest request) {
    logger.error(EXCEPTION_HANDLING_MESSAGE, exception.getClass().getName(), exception.getMessage());
    ErrorDetails details = getErrorDetails("AUTHZ-FAILURE-002",
            "JWT Token Expired!", request, HttpStatus.FORBIDDEN);
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(details);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorDetails> handleException(Exception exception,
                                                      HttpServletRequest request) {
    logger.error("Unknown Exception handling : {}", exception.getClass().getName());
    ErrorDetails details = getErrorDetails("ERROR-UNKNOWN",
            "UnHandled error occurred : " + exception.getMessage(), request, HttpStatus.UNAUTHORIZED);
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(details);
  }

  private static ErrorDetails getErrorDetails(String errorCode, String exception,
                                              HttpServletRequest request, HttpStatus httpStatus) {
    return ResponseMapper.buildErrorResponse(errorCode, exception,
            request.getServletPath(), httpStatus);
  }
}
