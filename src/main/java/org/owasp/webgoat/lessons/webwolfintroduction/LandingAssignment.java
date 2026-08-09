/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class LandingAssignment implements AssignmentEndpoint {
  private static final int CODE_BYTES = 24;

  private final String landingPageUrl;
  private final SecureRandom secureRandom = new SecureRandom();
  private final Map<String, String> pendingCodes = new ConcurrentHashMap<>();

  public LandingAssignment(@Value("${webwolf.landingpage.url}") String landingPageUrl) {
    this.landingPageUrl = landingPageUrl;
  }

  @PostMapping("/WebWolf/landing")
  @ResponseBody
  public AttackResult click(String uniqueCode, @CurrentUsername String username) {
    String expectedCode = pendingCodes.remove(username);
    if (validCode(expectedCode, uniqueCode)) {
      return success(this).build();
    }
    return failed(this).feedback("webwolf.landing_wrong").build();
  }

  @GetMapping("/WebWolf/landing/password-reset")
  public ModelAndView openPasswordReset(@CurrentUsername String username) {
    String uniqueCode = createUniqueCode();
    pendingCodes.put(username, uniqueCode);
    ModelAndView modelAndView = new ModelAndView();
    modelAndView.addObject(
        "webwolfLandingPageUrl", landingPageUrl.replace("//landing", "/landing"));
    modelAndView.addObject("uniqueCode", uniqueCode);

    modelAndView.setViewName("lessons/webwolfintroduction/templates/webwolfPasswordReset.html");
    return modelAndView;
  }

  private String createUniqueCode() {
    byte[] code = new byte[CODE_BYTES];
    secureRandom.nextBytes(code);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(code);
  }

  private boolean validCode(String expectedCode, String presentedCode) {
    if (expectedCode == null
        || presentedCode == null
        || expectedCode.length() != presentedCode.length()) {
      return false;
    }
    return MessageDigest.isEqual(
        expectedCode.getBytes(StandardCharsets.UTF_8),
        presentedCode.getBytes(StandardCharsets.UTF_8));
  }
}
