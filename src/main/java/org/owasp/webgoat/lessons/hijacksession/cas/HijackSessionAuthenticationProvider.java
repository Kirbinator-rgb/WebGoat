/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Queue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.DoublePredicate;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.ApplicationScope;

/**
 * @author Angel Olle Blazquez
 */

@ApplicationScope
@Component
public class HijackSessionAuthenticationProvider implements AuthenticationProvider<Authentication> {

  private static final int SESSION_ID_BYTES = 32;
  protected static final int MAX_SESSIONS = 50;

  private final Queue<String> sessions = new ArrayDeque<>();
  private final SecureRandom secureRandom = new SecureRandom();

  private static final DoublePredicate PROBABILITY_DOUBLE_PREDICATE = pr -> pr < 0.75;

  @Override
  public Authentication authenticate(Authentication authentication) {
    if (authentication == null) {
      return newAuthentication();
    }

    if (StringUtils.isNotEmpty(authentication.getId())
        && containsSession(authentication.getId())) {
      authentication.setAuthenticated(true);
      return authentication;
    }

    if (StringUtils.isEmpty(authentication.getId())) {
      authentication.setId(generateSessionId());
    }

    authorizedUserAutoLogin();

    return authentication;
  }

  protected void authorizedUserAutoLogin() {
    if (!PROBABILITY_DOUBLE_PREDICATE.test(ThreadLocalRandom.current().nextDouble())) {
      Authentication authentication = newAuthentication();
      authentication.setAuthenticated(true);
      addSession(authentication.getId());
    }
  }

  protected synchronized boolean addSession(String sessionId) {
    if (StringUtils.isBlank(sessionId)) {
      return false;
    }
    if (sessions.size() >= MAX_SESSIONS) {
      sessions.remove();
    }
    return sessions.add(sessionId);
  }

  protected synchronized int getSessionsSize() {
    return sessions.size();
  }

  private synchronized boolean containsSession(String sessionId) {
    return sessions.contains(sessionId);
  }

  private Authentication newAuthentication() {
    return Authentication.builder().id(generateSessionId()).build();
  }

  private String generateSessionId() {
    // ASVS V7.2/V11.5: session identifiers require at least 128 bits from a CSPRNG.
    byte[] randomBytes = new byte[SESSION_ID_BYTES];
    secureRandom.nextBytes(randomBytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
  }
}
