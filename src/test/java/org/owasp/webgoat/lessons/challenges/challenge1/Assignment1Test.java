/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import static org.assertj.core.api.Assertions.assertThat;
import static org.owasp.webgoat.lessons.challenges.SolutionConstants.PASSWORD;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

class Assignment1Test {

  @Test
  void logoDoesNotContainAInjectedPasswordPin() throws Exception {
    byte[] original =
        new ClassPathResource("lessons/challenges/images/webgoat2.png")
            .getInputStream()
            .readAllBytes();

    assertThat(new ImageServlet().logo()).isEqualTo(original);
  }

  @Test
  void formerSteganographicPasswordDoesNotAuthenticate() {
    var result = new Assignment1(null).completed("admin", PASSWORD.replace("1234", "0000"));

    assertThat(result.assignmentSolved()).isFalse();
  }
}
