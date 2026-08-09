/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class HtmlTamperingTaskTest extends LessonTest {

  @ParameterizedTest
  @CsvSource({"1,2999.99", "1,1.00", "2,0", "NaN,NaN", "101,302998.99"})
  void clientSuppliedTotalsNeverControlCheckout(String quantity, String total) throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/HtmlTampering/task")
                .param("QTY", quantity)
                .param("Total", total))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}
