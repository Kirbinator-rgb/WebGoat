/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

class EncDecTest {

  @Test
  @DisplayName("Signed cookie round trip")
  void signedCookieRoundTrip() {
    String encoded = EncDec.encode("WebGoat");

    assertThat(encoded).contains(".").doesNotContain("webgoat");
    assertThat(EncDec.decode(encoded)).isEqualTo("webgoat");
  }

  @Test
  @DisplayName("Tampered username is rejected")
  void tamperedCookieIsRejected() {
    String encoded = EncDec.encode("webgoat");
    String[] parts = encoded.split("\\.");
    String payload =
        new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8)
            .replace("webgoat", "tom");
    String tampered =
        Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8))
            + "."
            + parts[1];

    assertThatThrownBy(() -> EncDec.decode(tampered))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid authentication cookie");
  }

  @Test
  @DisplayName("Legacy reversible cookie is rejected")
  void legacyCookieIsRejected() {
    assertThatThrownBy(() -> EncDec.decode("NjI2MTcwNGI3YTQxNGE1OTU2NzQ2ZDZmNzQ="))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("null encode test")
  void testNullEncode() {
    assertThat(EncDec.encode(null)).isNull();
  }

  @Test
  @DisplayName("null decode test")
  void testNullDecode() {
    assertThat(EncDec.decode(null)).isNull();
  }

}
