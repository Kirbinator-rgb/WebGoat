/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge8;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
class Assignment8Test extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void getRequestIsDeniedWithoutFlag() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/challenge/8/vote/5"))
        .andExpect(status().isOk())
        .andExpect(header().doesNotExist("X-FlagController"))
        .andExpect(jsonPath("$.error", is(true)));
  }

  @Test
  void headRequestCannotBypassMethodAuthorization() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.head("/challenge/8/vote/5"))
        .andExpect(status().isOk())
        .andExpect(header().doesNotExist("X-FlagController"));
  }

  @Test
  void postRequestIsNotMappedToVotingEndpoint() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/challenge/8/vote/5"))
        .andExpect(status().isMethodNotAllowed())
        .andExpect(header().doesNotExist("X-FlagController"));
  }
}
