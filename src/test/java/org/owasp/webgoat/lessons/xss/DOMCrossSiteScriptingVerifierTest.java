/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class DOMCrossSiteScriptingVerifierTest {

  private final DOMCrossSiteScriptingVerifier endpoint = new DOMCrossSiteScriptingVerifier();

  @Test
  void doesNotTrustAClientSubmittedCallbackValue() {
    var result = endpoint.completed("known-session-value");

    assertThat(result.assignmentSolved()).isFalse();
  }
}
