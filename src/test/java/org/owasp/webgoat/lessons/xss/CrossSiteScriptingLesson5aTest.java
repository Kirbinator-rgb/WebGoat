/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class CrossSiteScriptingLesson5aTest extends LessonTest {

  @Test
  void encodesReflectedCreditCardInput() throws Exception {
    MvcResult result =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get("/CrossSiteScripting/attack5a")
                    .param("QTY1", "1")
                    .param("QTY2", "1")
                    .param("QTY3", "1")
                    .param("QTY4", "1")
                    .param("field1", "<script>alert('xss')</script>")
                    .param("field2", "111"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
            .andReturn();

    String response = result.getResponse().getContentAsString();
    assertThat(response)
        .doesNotContain("<script>alert")
        .contains("&lt;script&gt;alert");
  }
}
