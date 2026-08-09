/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Assignment1 implements AssignmentEndpoint {
  private static final String ADMIN_PASSWORD = createAdminPassword();

  private final Flags flags;

  public Assignment1(Flags flags) {
    this.flags = flags;
  }

  @PostMapping("/challenge/1")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    boolean ipAddressKnown = true;
    boolean passwordCorrect =
        "admin".equals(username) && ADMIN_PASSWORD.equals(password);
    if (passwordCorrect && ipAddressKnown) {
      return success(this).feedback("challenge.solved").feedbackArgs(flags.getFlag(1)).build();
    } else if (passwordCorrect) {
      return failed(this).feedback("ip.address.unknown").build();
    }
    return failed(this).build();
  }

  private static String createAdminPassword() {
    byte[] randomPassword = new byte[24];
    new SecureRandom().nextBytes(randomPassword);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(randomPassword);
  }
}
