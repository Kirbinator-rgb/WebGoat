/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

/** Created by appsec on 7/18/17. */
public class AccountVerificationHelper {

  // simulating database storage of verification credentials
  private static final Integer VERIFY_USER_ID = 12309746;
  private static final Map<String, String> USER_SECURITY_QUESTIONS =
      Map.of("secQuestion0", "Dr. Watson", "secQuestion1", "Baker Street");
  private static final Map<Integer, Map<String, String>> SECURITY_QUESTION_STORE =
      Map.of(VERIFY_USER_ID, USER_SECURITY_QUESTIONS);

  // end 'data store set up'

  public boolean verifyAccount(Integer userId, Map<String, String> submittedQuestions) {
    Map<String, String> expectedQuestions = SECURITY_QUESTION_STORE.get(userId);
    if (expectedQuestions == null || !submittedQuestions.keySet().equals(expectedQuestions.keySet())) {
      return false;
    }

    // ASVS V6.3: every required authentication answer must match; missing fields fail closed.
    boolean allAnswersMatch = true;
    for (Map.Entry<String, String> question : expectedQuestions.entrySet()) {
      allAnswersMatch &=
          constantTimeEquals(question.getValue(), submittedQuestions.get(question.getKey()));
    }
    return allAnswersMatch;
  }

  private boolean constantTimeEquals(String expected, String submitted) {
    return submitted != null
        && MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8), submitted.getBytes(StandardCharsets.UTF_8));
  }
}
