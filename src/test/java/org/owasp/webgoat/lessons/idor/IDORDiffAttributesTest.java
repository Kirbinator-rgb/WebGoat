/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class IDORDiffAttributesTest {

  private final IDORDiffAttributes endpoint = new IDORDiffAttributes();

  @Test
  void doesNotConfirmProtectedAttributeNames() {
    var result = endpoint.completed("userId,role");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
  }

  @Test
  void doesNotConfirmProtectedAttributeNamesInReverseOrder() {
    var result = endpoint.completed("role,userId");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
  }
}
