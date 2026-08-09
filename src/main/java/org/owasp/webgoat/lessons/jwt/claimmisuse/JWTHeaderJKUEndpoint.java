/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/JWT/")
@RestController
@AssignmentHints({
  "jwt-jku-hint1",
  "jwt-jku-hint2",
  "jwt-jku-hint3",
  "jwt-jku-hint4",
  "jwt-jku-hint5"
})
public class JWTHeaderJKUEndpoint implements AssignmentEndpoint {

  private static final int MAX_TOKEN_LENGTH = 4096;
  private static final Pattern KEY_ID_PATTERN = Pattern.compile("[A-Za-z0-9_-]{1,64}");
  private static final URL TRUSTED_JWKS_URL =
      createUrl(
          "https://cognito-idp.us-east-1.amazonaws.com/webgoat/.well-known/jwks.json");

  private final URL trustedJwksUrl;
  private final JwkProvider jwkProvider;

  public JWTHeaderJKUEndpoint() {
    this(TRUSTED_JWKS_URL);
  }

  JWTHeaderJKUEndpoint(URL trustedJwksUrl) {
    this.trustedJwksUrl = Objects.requireNonNull(trustedJwksUrl);
    this.jwkProvider =
        new JwkProviderBuilder(trustedJwksUrl)
            .cached(5, Duration.ofHours(1))
            .rateLimited(10, 1, TimeUnit.MINUTES)
            .timeouts(2000, 2000)
            .build();
  }

  @PostMapping("jku/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("jku/delete")
  public @ResponseBody AttackResult deleteAccount(@RequestParam("token") String token) {
    if (StringUtils.isBlank(token) || token.length() > MAX_TOKEN_LENGTH) {
      return failed(this).feedback("jwt-invalid-token").build();
    }

    try {
      var decodedJwt = JWT.decode(token);
      String keyId = decodedJwt.getKeyId();
      String jku = decodedJwt.getHeaderClaim("jku").asString();
      if (!"RS256".equals(decodedJwt.getAlgorithm())
          || !KEY_ID_PATTERN.matcher(StringUtils.defaultString(keyId)).matches()
          || !trustedJwksUrl.toExternalForm().equals(jku)) {
        return failed(this).feedback("jwt-invalid-token").build();
      }

      // ASVS V9.1/V13.2: resolve keys only through the server-owned, bounded provider.
      var jwk = jwkProvider.get(keyId);
      var algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey());
      JWT.require(algorithm).build().verify(decodedJwt);

      String username = decodedJwt.getClaim("username").asString();
      if ("Jerry".equals(username)) {
        return failed(this).feedback("jwt-final-jerry-account").build();
      }
      if ("Tom".equals(username)) {
        return success(this).build();
      }
      return failed(this).feedback("jwt-final-not-tom").build();
    } catch (JWTVerificationException | JwkException | ClassCastException e) {
      return failed(this).feedback("jwt-invalid-token").build();
    }
  }

  private static URL createUrl(String value) {
    try {
      return URI.create(value).toURL();
    } catch (IllegalArgumentException | MalformedURLException e) {
      throw new IllegalStateException("Invalid trusted JWKS URL", e);
    }
  }
}
