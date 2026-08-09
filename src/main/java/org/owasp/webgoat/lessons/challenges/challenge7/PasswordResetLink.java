/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * @author nbaars
 * @since 8/17/17.
 */
public class PasswordResetLink {

  private static final int TOKEN_BYTES = 32;

  private final SecureRandom secureRandom = new SecureRandom();

  public String createPasswordReset() {
    // ASVS V6.3: generate reset credentials from a CSPRNG with at least 128 bits of entropy.
    byte[] token = new byte[TOKEN_BYTES];
    secureRandom.nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
  }
}
