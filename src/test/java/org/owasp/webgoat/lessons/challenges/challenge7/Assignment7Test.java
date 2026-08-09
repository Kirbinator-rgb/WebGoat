/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.challenges.Email;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.client.RestTemplate;

class Assignment7Test extends LessonTest {
  private static final String CHALLENGE_PATH = "/challenge/7";
  private static final String RESET_PASSWORD_PATH = CHALLENGE_PATH + "/reset-password";
  private static final String GIT_PATH = CHALLENGE_PATH + "/.git";
  private static final String LEGACY_ADMIN_LINK = "375afe1104f4a487a73823c50a9292a2";
  private static final Pattern RESET_LINK_PATTERN = Pattern.compile("reset-password/([A-Za-z0-9_-]+)");

  @MockBean private RestTemplate restTemplate;

  @Value("${webwolf.mail.url}")
  String webWolfMailURL;

  @Test
  @DisplayName("Predictable and unknown password-reset links are rejected")
  void predictableResetPasswordLinksAreRejected() throws Exception {
    ResultActions result =
        mockMvc.perform(MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/any"));
    result.andExpect(status().is(equalTo(HttpStatus.I_AM_A_TEAPOT.value())));

    result =
        mockMvc.perform(MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/" + LEGACY_ADMIN_LINK));
    result.andExpect(status().is(equalTo(HttpStatus.I_AM_A_TEAPOT.value())));
  }

  @Test
  @DisplayName("Issued admin reset links are random and single-use")
  void issuedAdminResetLinkIsRandomAndSingleUse() throws Exception {
    ResultActions result =
        mockMvc.perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("email", "admin@webgoat-cloud.net"));
    result.andExpect(status().isOk());
    result.andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));

    ArgumentCaptor<Email> mailCaptor = ArgumentCaptor.forClass(Email.class);
    verify(restTemplate).postForEntity(eq(webWolfMailURL), mailCaptor.capture(), eq(Object.class));
    String resetLink = resetLinkFrom(mailCaptor.getValue());
    org.hamcrest.MatcherAssert.assertThat(resetLink, matchesPattern("[A-Za-z0-9_-]{43}"));

    mockMvc
        .perform(MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/" + resetLink))
        .andExpect(status().isAccepted());
    mockMvc
        .perform(MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/" + resetLink))
        .andExpect(status().is(equalTo(HttpStatus.I_AM_A_TEAPOT.value())));
  }

  @Test
  @DisplayName("Malformed email input does not create a reset credential")
  void malformedEmailDoesNotCreateResetCredential() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post(CHALLENGE_PATH).param("email", "not-an-email"))
        .andExpect(status().isOk());

    verify(restTemplate, never()).postForEntity(eq(webWolfMailURL), any(), eq(Object.class));
  }

  @Test
  @DisplayName("Source-control metadata is not exposed")
  void gitMetadataIsNotExposed() throws Exception {
    ResultActions result = mockMvc.perform(MockMvcRequestBuilders.get(GIT_PATH));
    result.andExpect(status().isNotFound());
  }

  private String resetLinkFrom(Email mail) {
    Matcher matcher = RESET_LINK_PATTERN.matcher(mail.getContents());
    org.junit.jupiter.api.Assertions.assertTrue(matcher.find());
    return matcher.group(1);
  }
}
