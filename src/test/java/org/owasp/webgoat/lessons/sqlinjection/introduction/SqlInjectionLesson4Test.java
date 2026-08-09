/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SqlInjectionLesson4Test {

  @Test
  void arbitrarySchemaChangesAreNotExecuted() {
    var result = new SqlInjectionLesson4().completed("ALTER TABLE employees ADD phone VARCHAR(20)");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
  }
}
