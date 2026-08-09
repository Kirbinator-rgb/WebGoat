/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class VulnerableComponentsLessonTest extends LessonTest {

  public static class CallbackTarget {

    private static boolean callbackInvoked;

    public String trigger() {
      callbackInvoked = true;
      return "called";
    }
  }

  @Test
  void acceptsExpectedContactData() throws Exception {
    String contact =
        "<contact><id>1</id><firstName>Alice</firstName><lastName>Doe</lastName>"
            + "<email>alice@example.org</email></contact>";

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/VulnerableComponents/attack1")
                .param("payload", contact))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void rejectsDynamicProxyBeforeCallbackRuns() throws Exception {
    CallbackTarget.callbackInvoked = false;
    String gadget =
        "<contact class='dynamic-proxy'>"
            + "<interface>org.owasp.webgoat.lessons.vulnerablecomponents.Contact</interface>"
            + "<handler class='java.beans.EventHandler'>"
            + "<target class='org.owasp.webgoat.lessons.vulnerablecomponents."
            + "VulnerableComponentsLessonTest$CallbackTarget'/>"
            + "<action>trigger</action>"
            + "</handler>"
            + "</contact>";

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/VulnerableComponents/attack1")
                .param("payload", gadget))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("vulnerable-components.close"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));

    assertFalse(CallbackTarget.callbackInvoked);
  }

  @Test
  void rejectsUnexpectedRootType() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/VulnerableComponents/attack1")
                .param("payload", "<string>unexpected</string>"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void rejectsMalformedXmlWithoutReturningParserDetails() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/VulnerableComponents/attack1")
                .param("payload", "not-xml"))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("vulnerable-components.close"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
