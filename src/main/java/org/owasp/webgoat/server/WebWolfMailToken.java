/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.server;

import java.security.SecureRandom;
import java.util.Base64;

public record WebWolfMailToken(String value) {

  public static final String HEADER_NAME = "X-WebWolf-Mail-Token";

  public static WebWolfMailToken create() {
    byte[] token = new byte[32];
    new SecureRandom().nextBytes(token);
    return new WebWolfMailToken(
        Base64.getUrlEncoder().withoutPadding().encodeToString(token));
  }
}
