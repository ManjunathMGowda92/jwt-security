package org.fourstack.jwt_security.exception;

public class InvalidCredentialsException extends RuntimeException{
  public InvalidCredentialsException(String message) {
    super(message);
  }

  public InvalidCredentialsException(String message, Throwable cause) {
    super(message, cause);
  }
}
