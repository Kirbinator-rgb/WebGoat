/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.XStreamException;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.NullPermission;
import com.thoughtworks.xstream.security.PrimitiveTypePermission;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"vulnerable.hint"})
@Slf4j
public class VulnerableComponentsLesson implements AssignmentEndpoint {

  private static final int MAX_PAYLOAD_LENGTH = 4096;

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    if (StringUtils.isBlank(payload) || payload.length() > MAX_PAYLOAD_LENGTH) {
      return failed(this).feedback("vulnerable-components.close").build();
    }

    try {
      Object deserialized = contactSerializer().fromXML(payload);
      if (!(deserialized instanceof ContactImpl contact)) {
        log.warn("Rejected XStream payload with an unexpected root type");
        return failed(this).feedback("vulnerable-components.close").build();
      }
      return failed(this).feedback("vulnerable-components.fromXML").feedbackArgs(contact).build();
    } catch (XStreamException exception) {
      log.warn("Rejected unsafe XStream payload: {}", exception.getClass().getSimpleName());
      return failed(this).feedback("vulnerable-components.close").build();
    }
  }

  private XStream contactSerializer() {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);

    // ASVS V1.5: start with no permissions and allow only the expected object graph.
    xstream.addPermission(NoTypePermission.NONE);
    xstream.addPermission(NullPermission.NULL);
    xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
    xstream.allowTypes(new Class<?>[] {ContactImpl.class, String.class, Integer.class});
    return xstream;
  }
}
