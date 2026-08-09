/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import javax.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
public class CryptoUtilTest {

  @Test
  public void testSigningAssignment() {
    try {
      KeyPair keyPair = CryptoUtil.generateKeyPair();
      RSAPublicKey rsaPubKey = (RSAPublicKey) keyPair.getPublic();
      String modulus = DatatypeConverter.printHexBinary(rsaPubKey.getModulus().toByteArray());
      String signature = CryptoUtil.signMessage(modulus, keyPair.getPrivate());
      log.debug("public exponent {}", rsaPubKey.getPublicExponent());
      assertThat(CryptoUtil.verifyAssignment(modulus, signature, keyPair.getPublic())).isTrue();
    } catch (Exception e) {
      fail("Signing failed");
    }
  }

  @Test
  void onlyExportsPublicKeyMaterial() throws Exception {
    KeyPair keyPair = CryptoUtil.generateKeyPair();

    assertThat(CryptoUtil.getPublicKeyInPEM(keyPair))
        .startsWith("-----BEGIN PUBLIC KEY-----")
        .doesNotContain("PRIVATE KEY")
        .doesNotContain(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
  }
}
