/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class ForgedReviewsTest {

  private static final String LEGACY_TOKEN = "2aa14227b9a13d0bede0388a7fba9aa9";
  private final ForgedReviews endpoint = new ForgedReviews();

  @Test
  void rejectsForgedReviewBeforeMutation() {
    String username = "csrf-forged-review-test";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Referer", "https://attacker.example/");

    var result = endpoint.createNewReview("forged", 5, LEGACY_TOKEN, request, username);

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(endpoint.retrieveReviews(username))
        .noneMatch(review -> "forged".equals(review.getText()));
  }

  @Test
  void permitsValidatedSameOriginReview() {
    String username = "csrf-valid-review-test";
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("X-Requested-With", "XMLHttpRequest");

    var result = endpoint.createNewReview("legitimate", 5, LEGACY_TOKEN, request, username);

    assertThat(result.assignmentSolved()).isTrue();
    assertThat(endpoint.retrieveReviews(username))
        .anyMatch(review -> "legitimate".equals(review.getText()));
  }
}
