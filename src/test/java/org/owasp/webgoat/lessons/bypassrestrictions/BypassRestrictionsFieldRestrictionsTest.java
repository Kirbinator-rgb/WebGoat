/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class BypassRestrictionsFieldRestrictionsTest extends LessonTest {

  @Test
  void browserAllowedValuesDoNotCompleteTheAssignment() throws Exception {
    submit("option1", "option2", "on", "12345", "change")
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  void modifiedRestrictedValuesAreRejected() throws Exception {
    submit("admin", "option3", "forged", "123456", "changed")
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  private org.springframework.test.web.servlet.ResultActions submit(
      String select, String radio, String checkbox, String shortInput, String readOnlyInput)
      throws Exception {
    return mockMvc.perform(
        MockMvcRequestBuilders.post("/BypassRestrictions/FieldRestrictions")
            .param("select", select)
            .param("radio", radio)
            .param("checkbox", checkbox)
            .param("shortInput", shortInput)
            .param("readOnlyInput", readOnlyInput));
  }
}
