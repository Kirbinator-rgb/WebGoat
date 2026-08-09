/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.http.ResponseEntity.ok;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.RandomStringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "jwt-refresh-hint1",
  "jwt-refresh-hint2",
  "jwt-refresh-hint3",
  "jwt-refresh-hint4"
})
public class JWTRefreshEndpoint implements AssignmentEndpoint {

  public static final String PASSWORD = "bm5nhSkxCXZkKRy4";
  private static final String JWT_PASSWORD = "bm5n3SkxCX4kKRy4";
  private static final String BEARER_PREFIX = "Bearer ";
  private static final int MAX_TOKEN_LENGTH = 4096;
  private static final List<String> validRefreshTokens = new ArrayList<>();

  @PostMapping(
      value = "/JWT/refresh/login",
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity follow(@RequestBody(required = false) Map<String, Object> json) {
    if (json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    String user = (String) json.get("user");
    String password = (String) json.get("password");

    if ("Jerry".equalsIgnoreCase(user) && PASSWORD.equals(password)) {
      return ok(createNewTokens(user));
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  private Map<String, Object> createNewTokens(String user) {
    Map<String, Object> claims = Map.of("admin", "false", "user", user);
    String token =
        Jwts.builder()
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, JWT_PASSWORD)
            .compact();
    Map<String, Object> tokenJson = new HashMap<>();
    String refreshToken = RandomStringUtils.randomAlphabetic(20);
    validRefreshTokens.add(refreshToken);
    tokenJson.put("access_token", token);
    tokenJson.put("refresh_token", refreshToken);
    return tokenJson;
  }

  @PostMapping("/JWT/refresh/checkout")
  @ResponseBody
  public ResponseEntity<AttackResult> checkout(
      @RequestHeader(value = "Authorization", required = false) String token) {
    if (token == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    try {
      Jws<Claims> jwt = parseSignedAccessToken(token);
      Claims claims = jwt.getBody();
      String user = (String) claims.get("user");
      if ("Tom".equals(user)) {
        return ok(success(this).build());
      }
      return ok(failed(this).feedback("jwt-refresh-not-tom").feedbackArgs(user).build());
    } catch (ExpiredJwtException e) {
      return ok(failed(this).output(e.getMessage()).build());
    } catch (JwtException e) {
      return ok(failed(this).feedback("jwt-invalid-token").build());
    }
  }

  @PostMapping("/JWT/refresh/newToken")
  @ResponseBody
  public ResponseEntity newToken(
      @RequestHeader(value = "Authorization", required = false) String token,
      @RequestBody(required = false) Map<String, Object> json) {
    if (token == null || json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    String user;
    String refreshToken;
    try {
      Jws<Claims> jwt = parseSignedAccessToken(token);
      user = (String) jwt.getBody().get("user");
      refreshToken = (String) json.get("refresh_token");
    } catch (ExpiredJwtException e) {
      if (!usesExpectedAlgorithm(e.getHeader())) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
      }
      user = (String) e.getClaims().get("user");
      refreshToken = (String) json.get("refresh_token");
    } catch (JwtException e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    if (user == null || refreshToken == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    } else if (validRefreshTokens.contains(refreshToken)) {
      validRefreshTokens.remove(refreshToken);
      return ok(createNewTokens(user));
    } else {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
  }

  private Jws<Claims> parseSignedAccessToken(String authorization) {
    if (!authorization.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
      throw new UnsupportedJwtException("Bearer authorization is required");
    }

    String compactToken = authorization.substring(BEARER_PREFIX.length());
    if (compactToken.isBlank() || compactToken.length() > MAX_TOKEN_LENGTH) {
      throw new UnsupportedJwtException("Invalid token length");
    }

    // ASVS V9.1: require a verified JWS and pin the server-selected signing algorithm.
    Jws<Claims> jwt =
        Jwts.parser().setSigningKey(JWT_PASSWORD).parseClaimsJws(compactToken);
    if (!usesExpectedAlgorithm(jwt.getHeader())) {
      throw new UnsupportedJwtException("Unexpected signing algorithm");
    }
    return jwt;
  }

  private boolean usesExpectedAlgorithm(Header header) {
    return SignatureAlgorithm.HS512.getValue().equals(header.get("alg"));
  }
}
