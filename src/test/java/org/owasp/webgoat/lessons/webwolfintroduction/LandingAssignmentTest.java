/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

class LandingAssignmentTest {

  @Test
  void usesAnUnpredictableSingleUseLandingCode() {
    LandingAssignment assignment = new LandingAssignment("http://localhost/WebWolf/landing");

    var resetPage = assignment.openPasswordReset("alice");
    String uniqueCode = (String) resetPage.getModel().get("uniqueCode");

    assertThat(uniqueCode).matches("[A-Za-z0-9_-]{32}");
    assertThat(uniqueCode).isNotEqualTo(StringUtils.reverse("alice"));
    assertThat(assignment.click(uniqueCode, "alice").assignmentSolved()).isTrue();
    assertThat(assignment.click(uniqueCode, "alice").assignmentSolved()).isFalse();
  }

  @Test
  void rejectsTheFormerPredictableCode() {
    LandingAssignment assignment = new LandingAssignment("http://localhost/WebWolf/landing");
    assignment.openPasswordReset("alice");

    assertThat(assignment.click("ecila", "alice").assignmentSolved()).isFalse();
  }
}
