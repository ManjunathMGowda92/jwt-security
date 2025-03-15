package org.fourstack.jwt_security.security.custom;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
  private final HandlerExceptionResolver exceptionResolver;

  public CustomAuthenticationEntryPoint(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver) {
    this.exceptionResolver = exceptionResolver;
  }

  /**
   * @param request       Http Servlet Request Object.
   * @param response      Http Servlet Response Object.
   * @param authException AuthenticationException object.
   * @throws IOException      throws IOException if any IO Error.
   * @throws ServletException throws ServletException if any Servlet related error.
   */
  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
                       AuthenticationException authException) throws IOException, ServletException {
    /*var message = (authException != null && authException.getMessage() != null) ?
            authException.getMessage() : "Authentication Failed";
    ErrorDetails details = ResponseMapper.buildErrorResponse("AUTHN-FAILURE-002",
            message, request.getServletPath(), HttpStatus.UNAUTHORIZED);
    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    String jsonString = ApplicationUtil.convertToString(details);
    response.getWriter().write(jsonString);*/
    exceptionResolver.resolveException(request, response, null, authException);
  }
}
