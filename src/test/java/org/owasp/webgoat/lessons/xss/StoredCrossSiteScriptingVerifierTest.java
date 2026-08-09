/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xss;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.lessons.xss.stored.StoredCrossSiteScriptingVerifier;

class StoredCrossSiteScriptingVerifierTest {

  private final StoredCrossSiteScriptingVerifier endpoint =
      new StoredCrossSiteScriptingVerifier();

  @Test
  void doesNotTrustAClientSubmittedCallbackValue() {
    var result = endpoint.completed("known-session-value");

    assertThat(result.assignmentSolved()).isFalse();
  }
}
