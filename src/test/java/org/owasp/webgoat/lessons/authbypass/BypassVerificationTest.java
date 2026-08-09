/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.mock.web.MockHttpServletRequest;

class BypassVerificationTest {

  private static final String USER_ID = "12309746";
  private LessonSession lessonSession;
  private VerifyAccount verifyAccount;

  @BeforeEach
  void setUp() {
    lessonSession = mock(LessonSession.class);
    verifyAccount = new VerifyAccount(lessonSession);
  }

  @Test
  void rejectsRenamedSecurityQuestionParameters() {
    MockHttpServletRequest request = requestWith("secQuestion2", "John", "secQuestion3", "Main");

    AttackResult result = verifyAccount.completed(USER_ID, "SEC_QUESTIONS", request);

    assertThat(result.assignmentSolved()).isFalse();
    verifyNoInteractions(lessonSession);
  }

  @Test
  void rejectsDuplicateSecurityQuestionValues() {
    MockHttpServletRequest request = validRequest();
    request.addParameter("secQuestion0", "second value");

    AttackResult result = verifyAccount.completed(USER_ID, "SEC_QUESTIONS", request);

    assertThat(result.assignmentSolved()).isFalse();
    verifyNoInteractions(lessonSession);
  }

  @Test
  void rejectsWrongAnswers() {
    MockHttpServletRequest request = requestWith("secQuestion0", "wrong", "secQuestion1", "wrong");

    AttackResult result = verifyAccount.completed(USER_ID, "SEC_QUESTIONS", request);

    assertThat(result.assignmentSolved()).isFalse();
    verifyNoInteractions(lessonSession);
  }

  @Test
  void rejectsUnsupportedVerificationMethod() {
    AttackResult result = verifyAccount.completed(USER_ID, "EMAIL", validRequest());

    assertThat(result.assignmentSolved()).isFalse();
    verifyNoInteractions(lessonSession);
  }

  @Test
  void verifiesAccountOnlyWhenEveryExpectedAnswerMatches() {
    AttackResult result = verifyAccount.completed(USER_ID, "SEC_QUESTIONS", validRequest());

    assertThat(result.assignmentSolved()).isTrue();
    verify(lessonSession).setValue("account-verified-id", USER_ID);
  }

  private MockHttpServletRequest validRequest() {
    return requestWith("secQuestion0", "Dr. Watson", "secQuestion1", "Baker Street");
  }

  private MockHttpServletRequest requestWith(
      String firstName, String firstValue, String secondName, String secondValue) {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addParameter(firstName, firstValue);
    request.addParameter(secondName, secondValue);
    return request;
  }
}
