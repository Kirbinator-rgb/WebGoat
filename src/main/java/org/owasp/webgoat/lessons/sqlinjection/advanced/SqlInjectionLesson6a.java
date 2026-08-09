/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.sqlinjection.introduction.SqlInjectionLesson5a;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint-advanced-6a-1",
      "SqlStringInjectionHint-advanced-6a-2",
      "SqlStringInjectionHint-advanced-6a-3",
      "SqlStringInjectionHint-advanced-6a-4",
      "SqlStringInjectionHint-advanced-6a-5"
    })
public class SqlInjectionLesson6a implements AssignmentEndpoint {
  private final LessonDataSource dataSource;

  public SqlInjectionLesson6a(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/attack6a")
  @ResponseBody
  public AttackResult completed(@RequestParam(value = "userid_6a") String userId) {
    return injectableQuery(userId);
  }

  public AttackResult injectableQuery(String accountName) {
    if (accountName.length() > 64) {
      return failed(this).build();
    }
    String query = "SELECT * FROM user_data WHERE last_name = ?";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(
                query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
      statement.setString(1, accountName);
      ResultSet results = statement.executeQuery();
      if (!results.first()) {
        return failed(this)
            .feedback("sql-injection.advanced.6a.no.results")
            .build();
      }
      return failed(this).output(SqlInjectionLesson5a.writeTable(results, results.getMetaData())).build();
    } catch (SQLException e) {
      return failed(this).build();
    }
  }
}
