/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.session.LessonSession;

class IDORViewOtherProfileTest {

  private LessonSession lessonSession;
  private IDORViewOtherProfile endpoint;

  @BeforeEach
  void setUp() {
    lessonSession = mock(LessonSession.class);
    endpoint = new IDORViewOtherProfile(lessonSession);
    when(lessonSession.getValue("idor-authenticated-as")).thenReturn("tom");
    when(lessonSession.getValue("idor-authenticated-user-id")).thenReturn("2342384");
  }

  @Test
  void rejectsAnotherUsersProfileId() {
    var result = endpoint.completed("2342388");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
  }

  @Test
  void returnsOnlyTheAuthenticatedUsersProfile() {
    var result = endpoint.completed("2342384");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).contains("2342384", "Tom Cat").doesNotContain("2342388");
  }

  @Test
  void rejectsProfileAccessWithoutAnAuthenticatedSession() {
    when(lessonSession.getValue("idor-authenticated-as")).thenReturn(null);
    when(lessonSession.getValue("idor-authenticated-user-id")).thenReturn(null);

    var result = endpoint.completed("2342388");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
  }
}
