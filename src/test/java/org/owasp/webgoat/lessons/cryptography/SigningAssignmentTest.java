/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import javax.xml.bind.DatatypeConverter;
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

  @Test
  void serverOwnedSigningKeyCannotCompleteTheClientAssignment() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest();
    SigningAssignment assignment = new SigningAssignment();
    assignment.getPublicKey(request);
    KeyPair keyPair = (KeyPair) request.getSession().getAttribute("keyPair");
    String modulus =
        DatatypeConverter.printHexBinary(
            ((RSAPublicKey) keyPair.getPublic()).getModulus().toByteArray());
    String signature = CryptoUtil.signMessage(modulus, keyPair.getPrivate());

    assertThat(assignment.completed(request, modulus, signature).assignmentSolved()).isFalse();
  }
}
