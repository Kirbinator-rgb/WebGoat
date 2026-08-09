/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.client.RestTemplate;

class ResetLinkHostValidationTest {

  @Test
  void resetEmailUsesTheConfiguredApplicationUrl() {
    RestTemplate restTemplate = mock(RestTemplate.class);
    ResetLinkAssignmentForgotPassword endpoint =
        new ResetLinkAssignmentForgotPassword(
            restTemplate, "https://trusted.example/WebGoat", "http://webwolf/mail");

    endpoint.sendPasswordResetLink("alice@webgoat-cloud.org", "alice");

    ArgumentCaptor<PasswordResetEmail> email = ArgumentCaptor.forClass(PasswordResetEmail.class);
    verify(restTemplate).postForEntity(eq("http://webwolf/mail"), email.capture(), eq(Object.class));
    assertThat(email.getValue().getContents())
        .contains("https://trusted.example/WebGoat/PasswordReset/reset/reset-password/")
        .doesNotContain("alice");
  }

  @Test
  void cannotCreateAResetLinkForAnotherAccount() {
    RestTemplate restTemplate = mock(RestTemplate.class);
    ResetLinkAssignmentForgotPassword endpoint =
        new ResetLinkAssignmentForgotPassword(
            restTemplate, "https://trusted.example/WebGoat", "http://webwolf/mail");

    assertThat(endpoint.sendPasswordResetLink("tom@webgoat-cloud.org", "alice").assignmentSolved())
        .isFalse();
    verify(restTemplate, never())
        .postForEntity(eq("http://webwolf/mail"), any(), eq(Object.class));
  }
}
