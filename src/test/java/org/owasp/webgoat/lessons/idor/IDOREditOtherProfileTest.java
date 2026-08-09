/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.owasp.webgoat.container.session.LessonSession;

class IDOREditOtherProfileTest {

  private LessonSession lessonSession;
  private IDOREditOtherProfile endpoint;

  @BeforeEach
  void setUp() {
    lessonSession = mock(LessonSession.class);
    endpoint = new IDOREditOtherProfile(lessonSession);
    when(lessonSession.getValue("idor-authenticated-as")).thenReturn("tom");
    when(lessonSession.getValue("idor-authenticated-user-id")).thenReturn("2342384");
  }

  @Test
  void rejectsEditingAnotherUsersProfile() {
    UserProfile submitted = new UserProfile();
    submitted.setUserId("2342388");
    submitted.setColor("red");
    submitted.setRole(1);

    var result = endpoint.completed("2342388", submitted);

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
    verify(lessonSession, never())
        .setValue(eq("idor-updated-other-profile"), org.mockito.ArgumentMatchers.any());
  }

  @Test
  void ignoresRoleAndIdentityDuringAnOwnProfileEdit() {
    UserProfile submitted = new UserProfile();
    submitted.setColor("black");
    submitted.setRole(1);

    var result = endpoint.completed("2342384", submitted);

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).contains("2342384", "color=black", "role=3");
    ArgumentCaptor<UserProfile> profileCaptor = ArgumentCaptor.forClass(UserProfile.class);
    verify(lessonSession).setValue(eq("idor-updated-own-profile"), profileCaptor.capture());
    assertThat(profileCaptor.getValue().getRole()).isEqualTo(3);
    assertThat(profileCaptor.getValue().getUserId()).isEqualTo("2342384");
  }

  @Test
  void rejectsClientIdentityMismatchOnTheAuthenticatedPath() {
    UserProfile submitted = new UserProfile();
    submitted.setUserId("2342388");
    submitted.setColor("black");

    var result = endpoint.completed("2342384", submitted);

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getOutput()).isNull();
    verify(lessonSession, never())
        .setValue(eq("idor-updated-own-profile"), org.mockito.ArgumentMatchers.any());
  }
}
