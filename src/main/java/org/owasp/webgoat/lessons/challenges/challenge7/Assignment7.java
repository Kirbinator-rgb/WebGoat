/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Email;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * @author nbaars
 * @since 4/8/17.
 */
@RestController
@Slf4j
public class Assignment7 implements AssignmentEndpoint {

  private static final int MAX_RESET_LINK_LENGTH = 64;
  private static final Duration RESET_LINK_TTL = Duration.ofMinutes(15);

  private static final String TEMPLATE =
      "Hi, you requested a password reset link, please use this <a target='_blank'"
          + " href='%s/challenge/7/reset-password/%s'>link</a> to reset your"
          + " password.\n"
          + " \n\n"
          + "If you did not request this password change you can ignore this message.\n"
          + "If you have any comments or questions, please do not hesitate to reach us at"
          + " support@webgoat-cloud.org\n\n"
          + "Kind regards, \n"
          + "Team WebGoat";

  private final Flags flags;
  private final RestTemplate restTemplate;
  private final String webWolfMailURL;
  private final String webGoatUrl;
  private final PasswordResetLink passwordResetLink = new PasswordResetLink();
  private final Map<String, PendingReset> pendingResets = new ConcurrentHashMap<>();

  public Assignment7(
      Flags flags,
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.url}") String webGoatUrl) {
    this.flags = flags;
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
    this.webGoatUrl = webGoatUrl;
  }

  @GetMapping("/challenge/7/reset-password/{link}")
  public ResponseEntity<String> resetPassword(@PathVariable(value = "link") String link) {
    // ASVS V6.3: reset links are bounded, expiring, single-use credentials.
    PendingReset pendingReset =
        StringUtils.hasText(link) && link.length() <= MAX_RESET_LINK_LENGTH
            ? pendingResets.remove(link)
            : null;
    if (pendingReset != null
        && pendingReset.expiresAt().isAfter(Instant.now())
        && pendingReset.username().equalsIgnoreCase("admin")) {
      return ResponseEntity.accepted()
          .body(
              "<h1>Success!!</h1>"
                  + "<img src='/WebGoat/images/hi-five-cat.jpg'>"
                  + "<br/><br/>Here is your flag: "
                  + flags.getFlag(7));
    }
    return ResponseEntity.status(HttpStatus.I_AM_A_TEAPOT)
        .body("That is not the reset link for admin");
  }

  @PostMapping("/challenge/7")
  @ResponseBody
  public AttackResult sendPasswordResetLink(@RequestParam String email) {
    String username = extractUsername(email);
    if (username != null) {
      String resetLink = passwordResetLink.createPasswordReset();
      pendingResets.put(resetLink, new PendingReset(username, Instant.now().plus(RESET_LINK_TTL)));
      try {
        Email mail =
            Email.builder()
                .title("Your password reset link for challenge 7")
                .contents(String.format(TEMPLATE, webGoatUrl, resetLink))
                .sender("password-reset@webgoat-cloud.net")
                .recipient(username)
                .time(LocalDateTime.now())
                .build();
        restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
      } catch (RuntimeException exception) {
        pendingResets.remove(resetLink);
        log.warn("Unable to deliver challenge 7 password reset email");
      }
    }
    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  private String extractUsername(String email) {
    if (!StringUtils.hasText(email) || email.length() > 254) {
      return null;
    }
    int separator = email.indexOf('@');
    if (separator <= 0 || separator != email.lastIndexOf('@') || separator == email.length() - 1) {
      return null;
    }
    String username = email.substring(0, separator);
    return username.length() <= 64 ? username : null;
  }

  private record PendingReset(String username, Instant expiresAt) {}
}
