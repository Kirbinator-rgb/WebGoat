/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PasswordResetLinkTest {

  @Test
  void generatesDistinctHighEntropyUrlSafeTokens() {
    PasswordResetLink generator = new PasswordResetLink();

    String first = generator.createPasswordReset();
    String second = generator.createPasswordReset();

    assertNotEquals(first, second);
    assertTrue(first.matches("[A-Za-z0-9_-]{43}"));
    assertTrue(second.matches("[A-Za-z0-9_-]{43}"));
  }
}
