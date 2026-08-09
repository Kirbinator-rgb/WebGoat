/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SqlInjectionLesson3Test {

  @Test
  void arbitraryUpdateStatementsAreNotExecuted() {
    var result =
        new SqlInjectionLesson3()
            .completed("UPDATE employees SET department='Sales' WHERE last_name='Barnett'");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
  }
}
