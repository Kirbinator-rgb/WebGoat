/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_ADMIN;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.CurrentUsername;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

/** Created by jason on 1/5/17. */
@Controller
@AllArgsConstructor
@Slf4j
public class MissingFunctionACUsers {

  private final MissingAccessControlUserRepository userRepository;

  @GetMapping(path = {"access-control/users"})
  @ResponseBody
  public ResponseEntity<Void> usersService() {
    // ASVS V4.1/V8.3: the legacy endpoint exposes no user records or derived credentials.
    return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
  }

  @GetMapping(
      path = {"access-control/users-admin-fix"},
      consumes = "application/json")
  @ResponseBody
  public ResponseEntity<List<DisplayUser>> usersFixed(@CurrentUsername String username) {
    var currentUser = userRepository.findByUsername(username);
    if (currentUser != null && currentUser.isAdmin()) {
      return ResponseEntity.ok(
          userRepository.findAllUsers().stream()
              .map(user -> new DisplayUser(user, PASSWORD_SALT_ADMIN))
              .collect(Collectors.toList()));
    }
    return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
  }

  @PostMapping(
      path = {"access-control/users", "access-control/users-admin-fix"},
      consumes = "application/json",
      produces = "application/json")
  @ResponseBody
  public ResponseEntity<User> addUser(
      @RequestBody User newUser, @CurrentUsername String currentUsername) {
    User currentUser = userRepository.findByUsername(currentUsername);
    if (currentUser == null || !currentUser.isAdmin()) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    if (!StringUtils.hasText(newUser.getUsername())
        || newUser.getUsername().length() > 64
        || !StringUtils.hasText(newUser.getPassword())
        || newUser.getPassword().length() > 128) {
      return ResponseEntity.badRequest().build();
    }

    try {
      // ASVS V4.1/V5.1: authorize the operation and ignore client-supplied privilege fields.
      User allowedUser = new User(newUser.getUsername(), newUser.getPassword(), false);
      userRepository.save(allowedUser);
      return ResponseEntity.ok(allowedUser);
    } catch (Exception ex) {
      log.error("Error creating new User", ex);
      return ResponseEntity.internalServerError().build();
    }

    // @RequestMapping(path = {"user/{username}","/"}, method = RequestMethod.DELETE, consumes =
    // "application/json", produces = "application/json")
    // TODO implement delete method with id param and authorization

  }
}
