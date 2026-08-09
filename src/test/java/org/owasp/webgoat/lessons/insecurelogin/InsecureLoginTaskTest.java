/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class InsecureLoginTaskTest {

  private final InsecureLoginTask task = new InsecureLoginTask();

  @Test
  void verifiesTheStoredPasswordHash() {
    assertThat(task.completed("CaptainJack", "BlackPearl").assignmentSolved()).isTrue();
  }

  @Test
  void rejectsAnIncorrectPassword() {
    assertThat(task.completed("CaptainJack", "incorrect").assignmentSolved()).isFalse();
  }

  @Test
  void noClientResourceContainsTheSharedCredentials() {
    assertThat(getClass().getResource("/lessons/insecurelogin/js/credentials.js")).isNull();
  }
}
