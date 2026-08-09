/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.util.List;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class BypassRestrictionsFrontendValidation implements AssignmentEndpoint {

  private static final int MAX_FIELD_LENGTH = 64;
  private static final List<Pattern> FIELD_PATTERNS =
      List.of(
          Pattern.compile("[a-z]{3}"),
          Pattern.compile("[0-9]{3}"),
          Pattern.compile("[a-zA-Z0-9 ]*"),
          Pattern.compile("one|two|three|four|five|six|seven|eight|nine"),
          Pattern.compile("\\d{5}"),
          Pattern.compile("\\d{5}(-\\d{4})?"),
          Pattern.compile("[2-9]\\d{2}-?\\d{3}-?\\d{4}"));

  @PostMapping("/BypassRestrictions/frontendValidation")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String field1,
      @RequestParam String field2,
      @RequestParam String field3,
      @RequestParam String field4,
      @RequestParam String field5,
      @RequestParam String field6,
      @RequestParam String field7,
      @RequestParam Integer error) {
    // ASVS V2.2: the server owns validation; the client-provided error counter is ignored.
    List<String> fields = List.of(field1, field2, field3, field4, field5, field6, field7);
    boolean valid = true;
    for (int index = 0; index < fields.size(); index++) {
      String field = fields.get(index);
      valid &=
          field.length() <= MAX_FIELD_LENGTH && FIELD_PATTERNS.get(index).matcher(field).matches();
    }
    if (!valid) {
      log.warn("Rejected a front-end validation bypass attempt");
    }
    return failed(this).build();
  }
}
