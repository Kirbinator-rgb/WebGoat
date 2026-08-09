/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class QuestionsAssignmentTest {

  private final QuestionsAssignment endpoint = new QuestionsAssignment();

  @Test
  void publicProfileAnswersCannotResetAnotherUsersPassword() {
    var result =
        endpoint.passwordReset(Map.of("username", "admin", "securityQuestion", "green"));

    assertThat(result.assignmentSolved()).isFalse();
  }
}
