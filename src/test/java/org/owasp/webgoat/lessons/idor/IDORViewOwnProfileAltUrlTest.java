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

class IDORViewOwnProfileAltUrlTest {

  private LessonSession lessonSession;
  private IDORViewOwnProfileAltUrl endpoint;

  @BeforeEach
  void setUp() {
    lessonSession = mock(LessonSession.class);
    endpoint = new IDORViewOwnProfileAltUrl(lessonSession);
  }

  @Test
  void doesNotResolveAClientSubmittedInternalProfilePath() {
    when(lessonSession.getValue("idor-authenticated-as")).thenReturn("tom");
    when(lessonSession.getValue("idor-authenticated-user-id")).thenReturn("2342384");

    var result = endpoint.completed("WebGoat/IDOR/profile/2342384");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
  }

  @Test
  void rejectsAnUnauthenticatedRequest() {
    when(lessonSession.getValue("idor-authenticated-as")).thenReturn(null);

    var result = endpoint.completed("WebGoat/IDOR/profile/2342384");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
  }
}
