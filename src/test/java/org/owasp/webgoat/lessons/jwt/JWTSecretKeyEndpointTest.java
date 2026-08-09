/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static io.jsonwebtoken.SignatureAlgorithm.HS256;
import static io.jsonwebtoken.SignatureAlgorithm.HS512;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.TextCodec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import javax.crypto.spec.SecretKeySpec;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
public class JWTSecretKeyEndpointTest extends LessonTest {

  private static final Key TEST_SIGNING_KEY =
      new SecretKeySpec(
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
              .getBytes(StandardCharsets.UTF_8),
          "HmacSHA256");

  private JWTSecretKeyEndpoint endpoint;

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    this.endpoint = new JWTSecretKeyEndpoint(TEST_SIGNING_KEY);
  }

  private Claims createClaims(String username) {
    Claims claims = Jwts.claims();
    claims.put("admin", "true");
    claims.put("user", "Tom");
    claims.setExpiration(Date.from(Instant.now().plus(Duration.ofDays(1))));
    claims.setIssuedAt(Date.from(Instant.now().plus(Duration.ofDays(1))));
    claims.setIssuer("iss");
    claims.setAudience("aud");
    claims.setSubject("sub");
    claims.put("username", username);
    claims.put("Email", "webgoat@webgoat.io");
    claims.put("Role", new String[] {"user"});
    return claims;
  }

  @Test
  public void validTokenForWebGoatCannotCompleteAssignment() {
    Claims claims = createClaims("WebGoat");
    String token = Jwts.builder().setClaims(claims).signWith(HS256, TEST_SIGNING_KEY).compact();

    assertThat(endpoint.login(token).assignmentSolved(), is(false));
    assertThat(endpoint.login(token).getFeedback(), is("jwt-invalid-token"));
  }

  @Test
  public void validTokenDoesNotAcceptCaseInsensitiveForgedUsername() {
    Claims claims = createClaims("webgoat");
    String token = Jwts.builder().setClaims(claims).signWith(HS256, TEST_SIGNING_KEY).compact();

    assertThat(endpoint.login(token).assignmentSolved(), is(false));
  }

  @Test
  public void oneOfClaimIsMissingShouldNotSolveAssignment() {
    Claims claims = createClaims("WebGoat");
    claims.remove("aud");
    String token = Jwts.builder().setClaims(claims).signWith(HS256, TEST_SIGNING_KEY).compact();

    assertThat(endpoint.login(token).getFeedback(), is("jwt-secret-claims-missing"));
  }

  @Test
  public void incorrectUser() {
    Claims claims = createClaims("Tom");
    String token = Jwts.builder().setClaims(claims).signWith(HS256, TEST_SIGNING_KEY).compact();

    assertThat(endpoint.login(token).getFeedback(), is("jwt-secret-incorrect-user"));
  }

  @Test
  public void incorrectToken() {
    Claims claims = createClaims("Tom");
    String token =
        Jwts.builder()
            .setClaims(claims)
            .signWith(HS256, TextCodec.BASE64.encode("wrong_password"))
            .compact();

    assertThat(endpoint.login(token).getFeedback(), is("jwt-invalid-token"));
  }

  @Test
  void unsignedToken() {
    Claims claims = createClaims("WebGoat");
    String token = Jwts.builder().setClaims(claims).compact();

    assertThat(endpoint.login(token).getFeedback(), is("jwt-invalid-token"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"victory", "business", "available", "shipping", "washington"})
  void weakDictionarySecretCannotForgeToken(String weakSecret) {
    String token =
        Jwts.builder()
            .setClaims(createClaims("WebGoat"))
            .signWith(HS256, TextCodec.BASE64.encode(weakSecret))
            .compact();

    assertThat(endpoint.login(token).getFeedback(), is("jwt-invalid-token"));
  }

  @Test
  void differentHmacAlgorithmIsRejected() {
    String token =
        Jwts.builder()
            .setClaims(createClaims("WebGoat"))
            .signWith(HS512, TEST_SIGNING_KEY)
            .compact();

    assertThat(endpoint.login(token).getFeedback(), is("jwt-invalid-token"));
  }

  @Test
  void issuedTokenIsValidButDoesNotGrantWebGoatUser() throws Exception {
    String token =
        mockMvc
            .perform(MockMvcRequestBuilders.get("/JWT/secret/gettoken"))
            .andReturn()
            .getResponse()
            .getContentAsString();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(
                    messages.getMessage("jwt-secret-incorrect-user", "default", "Tom"))));
  }
}
