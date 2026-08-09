/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class SqlInjectionChallengeTest extends LessonTest {

  @Test
  void registrationInputCannotProbeTomsPassword() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "tom' AND substring(password,1,1)='t")
                .param("email_reg", "someone@example.org")
                .param("password_reg", "not-toms-password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/login")
                .param("username_login", "tom")
                .param("password_login", "not-toms-password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
