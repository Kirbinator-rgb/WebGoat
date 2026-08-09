/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class MissingFunctionACUsersTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void unauthenticatedUserListingIsForbidden() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/access-control/users")
                .header("Content-type", "application/json"))
        .andExpect(status().isForbidden());

    mockMvc
        .perform(MockMvcRequestBuilders.get("/access-control/users"))
        .andExpect(status().isForbidden());
  }

  @Test
  void addUser() throws Exception {
    var user =
        """
        {"username":"newUser","password":"newUser12","admin": "true"}
        """;
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/access-control/users")
                .header("Content-type", "application/json")
                .content(user))
        .andExpect(status().isOk());

  }
}
