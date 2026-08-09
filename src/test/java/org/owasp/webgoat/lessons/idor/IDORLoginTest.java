/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class IDORLoginTest {

  private final IDORLogin endpoint = new IDORLogin();

  @Test
  void rejectsThePublishedSharedCredential() {
    var result = endpoint.completed("tom", "cat");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
  }

  @Test
  void rejectsOtherLessonLocalCredentials() {
    var result = endpoint.completed("bill", "buffalo");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
  }
}
