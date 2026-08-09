/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.requests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.webwolf.WebSecurityConfig;
import org.owasp.webgoat.webwolf.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(LandingPage.class)
@Import(WebSecurityConfig.class)
class LandingPageTest {

  @Autowired private MockMvc mvc;
  @MockBean private ClientRegistrationRepository clientRegistrationRepository;
  @MockBean private UserService userService;

  @Test
  void anonymousRequestsMustAuthenticate() throws Exception {
    mvc.perform(get("/landing/callback"))
        .andExpect(status().isFound())
        .andExpect(redirectedUrl("http://localhost/login"));
  }

  @Test
  @WithMockUser(username = "webgoat")
  void authenticatedRequestsRemainAvailable() throws Exception {
    mvc.perform(get("/landing/callback")).andExpect(status().isOk());
  }
}
