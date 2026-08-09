/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.client.RestTemplate;

class SimpleMailAssignmentTest {

  @Test
  void resetUsesAnUnpredictableOneTimePassword() {
    RestTemplate restTemplate = mock(RestTemplate.class);
    SimpleMailAssignment endpoint = new SimpleMailAssignment(restTemplate, "http://webwolf/mail");

    endpoint.resetPassword("alice@example.org", "alice");

    ArgumentCaptor<PasswordResetEmail> email = ArgumentCaptor.forClass(PasswordResetEmail.class);
    verify(restTemplate).postForEntity(eq("http://webwolf/mail"), email.capture(), eq(Object.class));
    String temporaryPassword =
        email.getValue().getContents().substring(email.getValue().getContents().lastIndexOf(' ') + 1);

    assertThat(temporaryPassword).isNotEqualTo("ecila").hasSizeGreaterThanOrEqualTo(32);
    assertThat(endpoint.login("alice@example.org", "ecila", "alice").assignmentSolved()).isFalse();
    assertThat(endpoint.login("alice@example.org", temporaryPassword, "alice").assignmentSolved())
        .isTrue();
    assertThat(endpoint.login("alice@example.org", temporaryPassword, "alice").assignmentSolved())
        .isFalse();
  }
}
