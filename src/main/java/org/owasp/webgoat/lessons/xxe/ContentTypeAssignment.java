/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xxe;

import static java.util.Optional.empty;
import static java.util.Optional.of;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Optional;
import org.owasp.webgoat.container.CurrentUser;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"xxe.hints.content.type.xxe.1", "xxe.hints.content.type.xxe.2"})
public class ContentTypeAssignment implements AssignmentEndpoint {

  private final CommentsCache comments;

  public ContentTypeAssignment(CommentsCache comments) {
    this.comments = comments;
  }

  @PostMapping(path = "xxe/content-type", consumes = APPLICATION_JSON_VALUE)
  @ResponseBody
  public AttackResult createNewUser(
      @RequestBody String commentStr, @CurrentUser WebGoatUser user) {
    // ASVS V4.2: constrain this boundary to the documented JSON representation.
    parseJson(commentStr).ifPresent(comment -> comments.addComment(comment, user, true));
    return failed(this).feedback("xxe.content.type.feedback.json").build();
  }

  protected Optional<Comment> parseJson(String comment) {
    ObjectMapper mapper = new ObjectMapper();
    try {
      return of(mapper.readValue(comment, Comment.class));
    } catch (IOException e) {
      return empty();
    }
  }

}
