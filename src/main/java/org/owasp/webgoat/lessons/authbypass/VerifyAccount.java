/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@AssignmentHints({
  "auth-bypass.hints.verify.1",
  "auth-bypass.hints.verify.2",
  "auth-bypass.hints.verify.3",
  "auth-bypass.hints.verify.4"
})
public class VerifyAccount implements AssignmentEndpoint {

  private static final String SECURITY_QUESTION_METHOD = "SEC_QUESTIONS";
  private static final Set<String> EXPECTED_QUESTION_KEYS =
      Set.of("secQuestion0", "secQuestion1");
  private static final int MAX_ANSWER_LENGTH = 200;

  private final LessonSession userSessionData;
  private final AccountVerificationHelper verificationHelper = new AccountVerificationHelper();

  public VerifyAccount(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @PostMapping(
      path = "/auth-bypass/verify-account",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(
      @RequestParam String userId, @RequestParam String verifyMethod, HttpServletRequest request) {
    Optional<Integer> parsedUserId = parseUserId(userId);
    Optional<Map<String, String>> submittedAnswers = parseSecurityQuestions(request);
    if (!SECURITY_QUESTION_METHOD.equals(verifyMethod)
        || parsedUserId.isEmpty()
        || submittedAnswers.isEmpty()
        || !verificationHelper.verifyAccount(parsedUserId.get(), submittedAnswers.get())) {
      log.warn("Account verification denied for an invalid method, account, or answer set");
      return failed(this).feedback("verify-account.failed").build();
    }

    userSessionData.setValue("account-verified-id", userId);
    log.info("Account verification succeeded for userId={}", parsedUserId.get());
    return success(this).feedback("verify-account.success").build();
  }

  private Optional<Map<String, String>> parseSecurityQuestions(HttpServletRequest request) {
    Map<String, String> answers = new HashMap<>();
    // ASVS V2.2: extract exact expected fields and reject duplicates or oversized values.
    for (String questionKey : EXPECTED_QUESTION_KEYS) {
      String[] values = request.getParameterValues(questionKey);
      if (values == null
          || values.length != 1
          || StringUtils.isBlank(values[0])
          || values[0].length() > MAX_ANSWER_LENGTH) {
        return Optional.empty();
      }
      answers.put(questionKey, values[0]);
    }
    return Optional.of(Map.copyOf(answers));
  }

  private Optional<Integer> parseUserId(String userId) {
    try {
      return Optional.of(Integer.valueOf(userId));
    } catch (NumberFormatException exception) {
      return Optional.empty();
    }
  }
}
