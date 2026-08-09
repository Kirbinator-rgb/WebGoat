/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import java.security.Key;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import javax.crypto.spec.SecretKeySpec;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"jwt-secret-hint1", "jwt-secret-hint2", "jwt-secret-hint3"})
public class JWTSecretKeyEndpoint implements AssignmentEndpoint {

  private static final int SIGNING_KEY_BYTES = 32;
  private static final int MAX_TOKEN_LENGTH = 4096;
  private static final String WEBGOAT_USER = "WebGoat";
  private static final List<String> EXPECTED_CLAIMS =
      List.of("iss", "iat", "exp", "aud", "sub", "username", "Email", "Role");
  private final Key signingKey;

  public JWTSecretKeyEndpoint() {
    this(generateSigningKey());
  }

  JWTSecretKeyEndpoint(Key signingKey) {
    this.signingKey = Objects.requireNonNull(signingKey);
  }

  @RequestMapping(path = "/JWT/secret/gettoken", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getSecretToken() {
    return Jwts.builder()
        .setIssuer("WebGoat Token Builder")
        .setAudience("webgoat.org")
        .setIssuedAt(Calendar.getInstance().getTime())
        .setExpiration(Date.from(Instant.now().plusSeconds(60)))
        .setSubject("tom@webgoat.org")
        .claim("username", "Tom")
        .claim("Email", "tom@webgoat.org")
        .claim("Role", new String[] {"Manager", "Project Administrator"})
        .signWith(SignatureAlgorithm.HS256, signingKey)
        .compact();
  }

  @PostMapping("/JWT/secret")
  @ResponseBody
  public AttackResult login(@RequestParam String token) {
    if (token == null || token.isBlank() || token.length() > MAX_TOKEN_LENGTH) {
      return invalidToken();
    }

    try {
      Jws<Claims> jwt = Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token);
      if (!SignatureAlgorithm.HS256.getValue().equals(jwt.getHeader().getAlgorithm())) {
        throw new UnsupportedJwtException("Unexpected signing algorithm");
      }

      Claims claims = jwt.getBody();
      if (!claims.keySet().containsAll(EXPECTED_CLAIMS)) {
        return failed(this).feedback("jwt-secret-claims-missing").build();
      }

      String user = claims.get("username", String.class);
      if (WEBGOAT_USER.equalsIgnoreCase(user)) {
        return success(this).build();
      }
      return failed(this).feedback("jwt-secret-incorrect-user").feedbackArgs(user).build();
    } catch (JwtException | IllegalArgumentException e) {
      return invalidToken();
    }
  }

  private AttackResult invalidToken() {
    return failed(this).feedback("jwt-invalid-token").build();
  }

  private static Key generateSigningKey() {
    // ASVS V9.1/V11.5: use an unpredictable key with enough entropy for token integrity.
    byte[] keyBytes = new byte[SIGNING_KEY_BYTES];
    new SecureRandom().nextBytes(keyBytes);
    return new SecretKeySpec(keyBytes, "HmacSHA256");
  }
}
