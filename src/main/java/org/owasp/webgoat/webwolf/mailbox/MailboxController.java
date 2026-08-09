/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.mailbox;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.owasp.webgoat.server.WebWolfMailToken;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

@RestController
@RequiredArgsConstructor
public class MailboxController {

  private final MailboxRepository mailboxRepository;
  private final WebWolfMailToken mailToken;

  @GetMapping("/mail")
  public ModelAndView mail(Authentication authentication, Model model) {
    String username = (null != authentication) ? authentication.getName() : "anonymous";
    ModelAndView modelAndView = new ModelAndView();
    List<Email> emails = mailboxRepository.findByRecipientOrderByTimeDesc(username);
    if (emails != null && !emails.isEmpty()) {
      modelAndView.addObject("total", emails.size());
      modelAndView.addObject("emails", emails);
    }
    modelAndView.setViewName("mailbox");
    model.addAttribute("username", username);
    return modelAndView;
  }

  @PostMapping("/mail")
  @ResponseStatus(HttpStatus.CREATED)
  public void sendEmail(
      @RequestBody Email email,
      @RequestHeader(value = WebWolfMailToken.HEADER_NAME, required = false)
          String presentedToken) {
    if (!validToken(presentedToken)) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN);
    }
    mailboxRepository.save(email);
  }

  @DeleteMapping("/mail")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public void deleteAllMail() {
    mailboxRepository.deleteAll();
  }

  private boolean validToken(String presentedToken) {
    if (presentedToken == null || presentedToken.length() != mailToken.value().length()) {
      return false;
    }
    return MessageDigest.isEqual(
        presentedToken.getBytes(StandardCharsets.UTF_8),
        mailToken.value().getBytes(StandardCharsets.UTF_8));
  }
}
