/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * @author nbaars
 * @since 11/17/17.
 */
public class CSRFFeedbackTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  public void postingJsonMessageThroughWebGoatShouldWork() throws Exception {
    mockMvc
        .perform(
            post("/csrf/feedback/message")
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"name\": \"Test\", \"email\": \"test1233@dfssdf.de\", \"subject\":"
                        + " \"service\", \"message\":\"dsaffd\"}"))
        .andExpect(status().isOk());
  }

  @Test
  public void rejectsCrossOriginFormCompatibleContentType() throws Exception {
    mockMvc
        .perform(
            post("/csrf/feedback/message")
                .contentType(MediaType.TEXT_PLAIN)
                .header("host", "localhost:8080")
                .header("referer", "webgoat.org")
                .content(
                    "{\"name\": \"Test\", \"email\": \"test1233@dfssdf.de\", \"subject\":"
                        + " \"service\", \"message\":\"dsaffd\"}"))
        .andExpect(status().isUnsupportedMediaType());
  }
}
