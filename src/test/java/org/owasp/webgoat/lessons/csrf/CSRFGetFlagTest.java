/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.mock.web.MockHttpServletRequest;

class CSRFGetFlagTest {

  private LessonSession lessonSession;
  private CSRFGetFlag endpoint;

  @BeforeEach
  void setUp() {
    lessonSession = mock(LessonSession.class);
    endpoint = new CSRFGetFlag(lessonSession, mock(PluginMessages.class));
  }

  @Test
  void rejectsAFormCompatibleCrossOriginRequest() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setParameter("csrf", "true");
    request.addHeader("Referer", "https://attacker.example/");

    var response = endpoint.invoke(request);

    assertThat(response).containsEntry("success", false).containsEntry("flag", null);
    verify(lessonSession, never())
        .setValue(eq("csrf-get-success"), org.mockito.ArgumentMatchers.any());
  }

  @Test
  void permitsTheSameOriginAjaxFlow() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("X-Requested-With", "XMLHttpRequest");

    var response = endpoint.invoke(request);

    assertThat(response).containsEntry("success", true);
    assertThat(response.get("flag")).isInstanceOf(Integer.class);
    verify(lessonSession).setValue(eq("csrf-get-success"), org.mockito.ArgumentMatchers.anyInt());
  }
}
