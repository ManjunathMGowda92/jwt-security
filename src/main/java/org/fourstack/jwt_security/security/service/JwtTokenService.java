package org.fourstack.jwt_security.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service class to generate and validate the JWT Tokens.
 */
@Service
public class JwtTokenService {

  public Claims extractClaims(String token, String secret) {
    return Jwts.parser()
            .verifyWith(getSecretKey(secret))
            .build()
            .parseSignedClaims(token)
            .getPayload();
  }

  public String getUsername(Claims claims) {
    return extractClaim(claims, claim -> claim.get("username", String.class));
  }

  private <T> T extractClaim(Claims claims, Function<Claims, T> claimResolver) {
    return claimResolver.apply(claims);
  }

  private SecretKey getSecretKey(String secret) {
    byte[] keyBytes = Decoders.BASE64.decode(secret);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public String generateToken(UserDetails userDetails, String secret) {
    Map<String, Object> extraClaims = new HashMap<>();
    extraClaims.put("username", userDetails.getUsername());
    extraClaims.put("authorities", userDetails.getAuthorities());
    return generateToken(extraClaims, secret);
  }

  private String generateToken(Map<String, Object> extraClaims, String secret) {
    return Jwts.builder()
            .issuer("Security Application")
            .subject("JWT Auth Token")
            .claims(extraClaims)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + (1000 * 60 * 60)))
            .signWith(getSecretKey(secret))
            .compact();
  }
}
