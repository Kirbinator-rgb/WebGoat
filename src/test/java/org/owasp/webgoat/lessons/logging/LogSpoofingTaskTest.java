/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class LogSpoofingTaskTest extends LessonTest {

  @ParameterizedTest
  @ValueSource(strings = {"guest\nadmin", "guest\r\nadmin", "guest%0Aadmin"})
  void lineBreakPayloadCannotForgeAdminLogEntry(String username) throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/LogSpoofing/log-spoofing")
                .param("username", username)
                .param("password", "irrelevant"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", not(containsString("admin"))));
  }
}
