/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.client.RestTemplate;

class MailAssignmentTest {
  private static final Pattern UNIQUE_CODE = Pattern.compile("unique code is: ([A-Za-z0-9_-]+)");

  @Test
  void sendsAnUnpredictableSingleUseCode() {
    RestTemplate restTemplate = mock(RestTemplate.class);
    MailAssignment assignment = new MailAssignment(restTemplate, "http://webwolf/mail");

    assignment.sendEmail("alice@webgoat.org", "alice");

    ArgumentCaptor<Email> email = ArgumentCaptor.forClass(Email.class);
    verify(restTemplate).postForEntity(eq("http://webwolf/mail"), email.capture(), eq(Object.class));
    var matcher = UNIQUE_CODE.matcher(email.getValue().getContents());
    assertThat(matcher.find()).isTrue();
    String uniqueCode = matcher.group(1);
    assertThat(uniqueCode).matches("[A-Za-z0-9_-]{32}").isNotEqualTo("ecila");
    assertThat(assignment.completed(uniqueCode, "alice").assignmentSolved()).isTrue();
    assertThat(assignment.completed(uniqueCode, "alice").assignmentSolved()).isFalse();
  }

  @Test
  void rejectsTheFormerPredictableCode() {
    RestTemplate restTemplate = mock(RestTemplate.class);
    MailAssignment assignment = new MailAssignment(restTemplate, "http://webwolf/mail");
    assignment.sendEmail("alice@webgoat.org", "alice");

    assertThat(assignment.completed("ecila", "alice").assignmentSolved()).isFalse();
  }

  @Test
  void rejectsMalformedRecipientAddresses() {
    RestTemplate restTemplate = mock(RestTemplate.class);
    MailAssignment assignment = new MailAssignment(restTemplate, "http://webwolf/mail");

    assertThat(assignment.sendEmail("invalid", "alice").assignmentSolved()).isFalse();
    verify(restTemplate, never())
        .postForEntity(eq("http://webwolf/mail"), any(), eq(Object.class));
  }
}
