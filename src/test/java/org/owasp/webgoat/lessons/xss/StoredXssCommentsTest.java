/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class StoredXssCommentsTest extends LessonTest {

  @Test
  void storesPhoneHomePayloadAsNonExecutableText() throws Exception {
    ResultActions results =
        mockMvc.perform(
            MockMvcRequestBuilders.post("/CrossSiteScriptingStored/stored-xss")
                .content(
                    "{\"text\":\"someTextHere<script>webgoat.customjs.phoneHome()</script>MoreTextHere\"}")
                .contentType(MediaType.APPLICATION_JSON));

    results.andExpect(status().isOk());
    results.andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void failure() throws Exception {
    ResultActions results =
        mockMvc.perform(
            MockMvcRequestBuilders.post("/CrossSiteScriptingStored/stored-xss")
                .content("{\"text\":\"someTextHere<script>alert('Xss')</script>MoreTextHere\"}")
                .contentType(MediaType.APPLICATION_JSON));

    results.andExpect(status().isOk());
    results.andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  public void encodesSeededComments() throws Exception {
    ResultActions taintedResults =
        mockMvc.perform(MockMvcRequestBuilders.get("/CrossSiteScriptingStored/stored-xss"));
    MvcResult mvcResult = taintedResults.andReturn();
    String body = mvcResult.getResponse().getContentAsString();
    org.assertj.core.api.Assertions.assertThat(body)
        .doesNotContain("<script>console.warn")
        .contains("&lt;script&gt;console.warn");
  }
}
