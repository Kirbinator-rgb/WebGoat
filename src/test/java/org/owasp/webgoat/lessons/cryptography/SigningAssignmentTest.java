/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class SigningAssignmentTest {

  @Test
  void signingKeyEndpointExposesOnlyPublicKeyMaterial() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();

    String response = new SigningAssignment().getPublicKey(request);
    KeyPair sessionKeyPair = (KeyPair) request.getSession().getAttribute("keyPair");

    assertThat(response)
        .startsWith("-----BEGIN PUBLIC KEY-----")
        .doesNotContain("PRIVATE KEY")
        .doesNotContain(
            Base64.getEncoder().encodeToString(sessionKeyPair.getPrivate().getEncoded()));
    assertThat(request.getSession().getAttribute("privateKeyString")).isNull();
  }
}
