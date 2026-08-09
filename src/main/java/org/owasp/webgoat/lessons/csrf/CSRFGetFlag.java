/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/30/17. */
@RestController
public class CSRFGetFlag {

  private final LessonSession userSessionData;
  private final PluginMessages pluginMessages;
  private final SecureRandom secureRandom = new SecureRandom();

  public CSRFGetFlag(LessonSession userSessionData, PluginMessages pluginMessages) {
    this.userSessionData = userSessionData;
    this.pluginMessages = pluginMessages;
  }

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {
    Map<String, Object> response = new HashMap<>();
    if (!"XMLHttpRequest".equals(req.getHeader("X-Requested-With"))) {
      response.put("success", false);
      response.put("message", "Request verification failed");
      response.put("flag", null);
      return response;
    }

    int flag = secureRandom.nextInt(65536);
    userSessionData.setValue("csrf-get-success", flag);
    response.put("success", true);
    response.put("message", pluginMessages.getMessage("csrf-get-null-referer.success"));
    response.put("flag", flag);
    return response;
  }
}
