/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class BypassRestrictionsFieldRestrictions implements AssignmentEndpoint {

  private static final Set<String> OPTIONS = Set.of("option1", "option2");

  @PostMapping("/BypassRestrictions/FieldRestrictions")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String select,
      @RequestParam String radio,
      @RequestParam(required = false) String checkbox,
      @RequestParam String shortInput,
      @RequestParam String readOnlyInput) {
    // ASVS V2.2: enforce every browser field restriction again at the server boundary.
    boolean valid =
        OPTIONS.contains(select)
            && OPTIONS.contains(radio)
            && (checkbox == null || "on".equals(checkbox))
            && shortInput.length() <= 5
            && "change".equals(readOnlyInput);
    if (!valid) {
      log.warn("Rejected a bypass attempt against server-side field restrictions");
    }
    return failed(this).build();
  }
}
