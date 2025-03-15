package org.fourstack.jwt_security.security.custom;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.fourstack.jwt_security.exception.ErrorDetails;
import org.fourstack.jwt_security.util.ApplicationUtil;
import org.fourstack.jwt_security.util.ResponseMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;


public class CustomAccessDeniedHandler implements AccessDeniedHandler {
  /**
   * Exception Handler class to handle the Access Denied cases. Method catches AccessDeniedException and
   * converts it into a custom error response.
   *
   * @param request               Http Servlet Request object.
   * @param response              Http Servlet Response object.
   * @param accessDeniedException AccessDeniedException object.
   * @throws IOException      throws IOException if any error occurs.
   * @throws ServletException throws ServletException if any error occurs.
   */
  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response,
                     AccessDeniedException accessDeniedException) throws IOException, ServletException {
    var message = (accessDeniedException != null && accessDeniedException.getMessage() != null) ?
            accessDeniedException.getMessage() : "Authorization failed";
    String path = request.getServletPath();
    response.setHeader("app-authorization", "Authorization-Failure");
    response.setStatus(HttpStatus.FORBIDDEN.value());
    response.setContentType("application/json");
    ErrorDetails errorDetails = ResponseMapper.buildErrorResponse("AUTHZ-FAILURE-001", message,
            path, HttpStatus.FORBIDDEN);
    String responseStr = ApplicationUtil.convertToString(errorDetails);
    response.getWriter().write(responseStr);
  }
}
