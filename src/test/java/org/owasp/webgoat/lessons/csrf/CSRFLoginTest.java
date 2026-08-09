/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CSRFLoginTest {

  private final CSRFLogin endpoint = new CSRFLogin();

  @Test
  void rejectsAFormCompatibleCrossOriginRequest() {
    var result = endpoint.completed("csrf-attacker", null);

    assertThat(result.assignmentSolved()).isFalse();
  }

  @Test
  void permitsTheSameOriginAjaxFlow() {
    var result = endpoint.completed("csrf-user", "XMLHttpRequest");

    assertThat(result.assignmentSolved()).isTrue();
  }
}
