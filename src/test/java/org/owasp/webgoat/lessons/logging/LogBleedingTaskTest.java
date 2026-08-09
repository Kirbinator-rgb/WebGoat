/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

@ExtendWith(OutputCaptureExtension.class)
class LogBleedingTaskTest extends LessonTest {

  @Test
  void taskInitializationDoesNotLogAdminCredential(CapturedOutput output) {
    new LogBleedingTask();

    assertThat(output).doesNotContain("Password for admin:");
  }

  @Test
  void guessedCredentialDoesNotCompleteAssignment() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/LogSpoofing/log-bleeding")
                .param("username", "Admin")
                .param("password", "guessed"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}
