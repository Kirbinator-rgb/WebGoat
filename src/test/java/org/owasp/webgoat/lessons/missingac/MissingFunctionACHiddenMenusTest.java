/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import java.io.IOException;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class MissingFunctionACHiddenMenusTest extends LessonTest {

  @Test
  void hiddenMenuNamesDoNotGrantAccess() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/hidden-menu")
                .param("hiddenMenu1", "Users")
                .param("hiddenMenu2", "Config"))
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("access-control.hidden-menus.failure"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void missingParametersDoNotCauseAuthorizationOrAnError() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/access-control/hidden-menu"))
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("access-control.hidden-menus.failure"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void unauthorizedAdminMenuIsAbsentFromThePage() throws IOException {
    String lessonHtml =
        new ClassPathResource("lessons/missingac/html/MissingFunctionAC.html")
            .getContentAsString(UTF_8);

    assertThat(lessonHtml)
        .doesNotContain("hidden-menu-item")
        .doesNotContain("access-control/users-admin-fix")
        .doesNotContain(">Config<");
  }
}
