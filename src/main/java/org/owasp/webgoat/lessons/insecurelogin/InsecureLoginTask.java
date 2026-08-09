/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class InsecureLoginTask implements AssignmentEndpoint {

  private static final String EXPECTED_USERNAME = "CaptainJack";
  private static final BCryptPasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();
  private static final String EXPECTED_PASSWORD_HASH =
      PASSWORD_ENCODER.encode(createPassword());

  @PostMapping("/InsecureLogin/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    // ASVS V6.2: verify passwords with an adaptive one-way hash, never a plaintext secret.
    if (EXPECTED_USERNAME.equals(username) && PASSWORD_ENCODER.matches(password, EXPECTED_PASSWORD_HASH)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  private static String createPassword() {
    byte[] password = new byte[24];
    new SecureRandom().nextBytes(password);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(password);
  }
}
