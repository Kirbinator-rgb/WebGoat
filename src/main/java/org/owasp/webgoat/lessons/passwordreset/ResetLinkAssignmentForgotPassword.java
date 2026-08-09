/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {
  private static final int RESET_TOKEN_BYTES = 32;

  private final RestTemplate restTemplate;
  private final String webGoatURL;
  private final String webWolfMailURL;
  private final SecureRandom secureRandom = new SecureRandom();

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webgoat.url}") String webGoatURL,
      @Value("${webwolf.mail.url}") String webWolfMailURL) {
    this.restTemplate = restTemplate;
    this.webGoatURL = webGoatURL;
    this.webWolfMailURL = webWolfMailURL;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, @CurrentUsername String username) {
    byte[] tokenBytes = new byte[RESET_TOKEN_BYTES];
    secureRandom.nextBytes(tokenBytes);
    String resetLink = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    ResetLinkAssignment.resetLinks.put(
        resetLink,
        new ResetLinkAssignment.PendingReset(
            email, username, Instant.now().plus(ResetLinkAssignment.RESET_LINK_TTL)));
    try {
      sendMailToUser(email, webGoatURL, resetLink);
    } catch (Exception e) {
      ResetLinkAssignment.resetLinks.remove(resetLink);
      return failed(this).output("E-mail can't be send. please try again.").build();
    }

    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String host, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, host, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }

}
