/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class MailAssignment implements AssignmentEndpoint {
  private static final int CODE_BYTES = 24;

  private final String webWolfURL;
  private final RestTemplate restTemplate;
  private final SecureRandom secureRandom = new SecureRandom();
  private final Map<String, String> pendingCodes = new ConcurrentHashMap<>();

  public MailAssignment(
      RestTemplate restTemplate, @Value("${webwolf.mail.url}") String webWolfURL) {
    this.restTemplate = restTemplate;
    this.webWolfURL = webWolfURL;
  }

  @PostMapping("/WebWolf/mail/send")
  @ResponseBody
  public AttackResult sendEmail(
      @RequestParam String email, @CurrentUsername String webGoatUsername) {
    String username = extractUsername(email);
    if (username != null && username.equalsIgnoreCase(webGoatUsername)) {
      String uniqueCode = createUniqueCode();
      Email mailEvent =
          Email.builder()
              .recipient(username)
              .title("Test messages from WebWolf")
              .contents(
                  "This is a test message from WebWolf, your unique code is: "
                      + uniqueCode)
              .sender("webgoat@owasp.org")
              .build();
      try {
        restTemplate.postForEntity(webWolfURL, mailEvent, Object.class);
      } catch (RestClientException e) {
        return informationMessage(this)
            .feedback("webwolf.email_failed")
            .output(e.getMessage())
            .build();
      }
      pendingCodes.put(webGoatUsername, uniqueCode);
      return informationMessage(this).feedback("webwolf.email_send").feedbackArgs(email).build();
    } else {
      return informationMessage(this)
          .feedback("webwolf.email_mismatch")
          .feedbackArgs(username)
          .build();
    }
  }

  @PostMapping("/WebWolf/mail")
  @ResponseBody
  public AttackResult completed(@RequestParam String uniqueCode, @CurrentUsername String username) {
    String expectedCode = pendingCodes.remove(username);
    if (validCode(expectedCode, uniqueCode)) {
      return success(this).build();
    } else {
      return failed(this).feedbackArgs("webwolf.code_incorrect").feedbackArgs(uniqueCode).build();
    }
  }

  private String extractUsername(String email) {
    if (email == null || email.length() > 254) {
      return null;
    }
    int separator = email.indexOf('@');
    if (separator <= 0 || separator != email.lastIndexOf('@') || separator == email.length() - 1) {
      return null;
    }
    return email.substring(0, separator);
  }

  private String createUniqueCode() {
    byte[] code = new byte[CODE_BYTES];
    secureRandom.nextBytes(code);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(code);
  }

  private boolean validCode(String expectedCode, String presentedCode) {
    if (expectedCode == null
        || presentedCode == null
        || expectedCode.length() != presentedCode.length()) {
      return false;
    }
    return MessageDigest.isEqual(
        expectedCode.getBytes(StandardCharsets.UTF_8),
        presentedCode.getBytes(StandardCharsets.UTF_8));
  }
}
