package org.fourstack.jwt_security.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

public final class ApplicationUtil {
  private ApplicationUtil(){
  }
  private static ObjectMapper objectMapper;

  private static ObjectMapper objectMapper() {
    if (objectMapper == null) {
      objectMapper = new ObjectMapper()
              .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
              .configure(SerializationFeature.WRITE_DATE_KEYS_AS_TIMESTAMPS, false)
              .configure(SerializationFeature.WRITE_DATES_WITH_CONTEXT_TIME_ZONE, false);
      objectMapper.findAndRegisterModules();
    }
    return objectMapper;
  }

  public static String convertToString(Object object) {
    if (object instanceof String str) {
      return str;
    }
    try {
      return objectMapper().writeValueAsString(object);
    } catch (Exception e) {
      return "";
    }
  }
}
