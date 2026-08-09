/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.TextCodec;
import java.sql.SQLException;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "jwt-kid-hint1",
  "jwt-kid-hint2",
  "jwt-kid-hint3",
  "jwt-kid-hint4",
  "jwt-kid-hint5",
  "jwt-kid-hint6"
})
@RequestMapping("/JWT/")
@Slf4j
public class JWTHeaderKIDEndpoint implements AssignmentEndpoint {

  private static final int MAX_TOKEN_LENGTH = 4096;
  private static final Pattern KEY_ID_PATTERN = Pattern.compile("[A-Za-z0-9_-]{1,20}");
  private final LessonDataSource dataSource;

  private JWTHeaderKIDEndpoint(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("kid/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("kid/delete")
  public @ResponseBody AttackResult deleteAccount(@RequestParam("token") String token) {
    if (StringUtils.isBlank(token) || token.length() > MAX_TOKEN_LENGTH) {
      return failed(this).feedback("jwt-invalid-token").build();
    }

    try {
      Jws<Claims> jwt =
          Jwts.parser().setSigningKeyResolver(new DatabaseKeyResolver()).parseClaimsJws(token);
      String username = jwt.getBody().get("username", String.class);
      if ("Jerry".equals(username)) {
        return failed(this).feedback("jwt-final-jerry-account").build();
      }
      if ("Tom".equals(username)) {
        return success(this).build();
      }
      return failed(this).feedback("jwt-final-not-tom").build();
    } catch (JwtException | IllegalArgumentException e) {
      return failed(this).feedback("jwt-invalid-token").build();
    }
  }

  private final class DatabaseKeyResolver extends SigningKeyResolverAdapter {

    @Override
    public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
      if (!SignatureAlgorithm.HS512.getValue().equals(header.getAlgorithm())) {
        throw new UnsupportedJwtException("Unexpected signing algorithm");
      }

      String keyId = header.getKeyId();
      if (keyId == null || !KEY_ID_PATTERN.matcher(keyId).matches()) {
        throw new UnsupportedJwtException("Invalid key identifier");
      }

      // ASVS V1.2/V9.1: validate the untrusted header, then bind it as query data.
      try (var connection = dataSource.getConnection();
          var statement = connection.prepareStatement("SELECT key FROM jwt_keys WHERE id = ?")) {
        statement.setString(1, keyId);
        try (var resultSet = statement.executeQuery()) {
          if (resultSet.next()) {
            return TextCodec.BASE64.decode(resultSet.getString(1));
          }
        }
      } catch (SQLException e) {
        log.warn("Unable to resolve JWT signing key", e);
        throw new UnsupportedJwtException("Signing key unavailable", e);
      }
      throw new UnsupportedJwtException("Unknown signing key");
    }
  }
}
