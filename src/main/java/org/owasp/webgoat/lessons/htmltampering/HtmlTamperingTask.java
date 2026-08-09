/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.math.BigDecimal;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
@Slf4j
public class HtmlTamperingTask implements AssignmentEndpoint {

  private static final BigDecimal UNIT_PRICE = new BigDecimal("2999.99");
  private static final int MAX_QUANTITY = 100;

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String QTY, @RequestParam(required = false) String Total) {
    try {
      if (QTY.length() > 3 || Total == null || Total.length() > 16) {
        throw new NumberFormatException("Checkout value exceeds allowed length");
      }
      int quantity = Integer.parseInt(QTY);
      if (quantity < 1 || quantity > MAX_QUANTITY) {
        throw new NumberFormatException("Quantity outside allowed range");
      }
      BigDecimal serverTotal = UNIT_PRICE.multiply(BigDecimal.valueOf(quantity));
      if (serverTotal.compareTo(new BigDecimal(Total)) != 0) {
        log.warn("Rejected a client-supplied checkout total");
      }
    } catch (NumberFormatException exception) {
      log.warn("Rejected invalid checkout quantity or total");
    }
    // ASVS V2.3: price and totals are derived exclusively from server-owned values.
    return failed(this).feedback("html-tampering.tamper.failure").build();
  }
}
