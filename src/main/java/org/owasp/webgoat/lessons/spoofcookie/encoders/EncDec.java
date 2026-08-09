/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

public class EncDec {

  private static final int KEY_BYTES = 32;
  private static final int MAX_COOKIE_LENGTH = 256;
  private static final Duration COOKIE_TTL = Duration.ofMinutes(15);
  private static final Pattern USERNAME_PATTERN = Pattern.compile("[a-z0-9._-]{1,64}");
  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
  private static final SecretKeySpec SIGNING_KEY = createSigningKey();

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String username = value.toLowerCase(Locale.ROOT);
    if (!USERNAME_PATTERN.matcher(username).matches()) {
      throw invalidCookie();
    }

    String payload = username + ":" + Instant.now().getEpochSecond();
    String encodedPayload = ENCODER.encodeToString(payload.getBytes(UTF_8));
    String signature = ENCODER.encodeToString(sign(encodedPayload.getBytes(US_ASCII)));
    return encodedPayload + "." + signature;
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }
    if (encodedValue.length() > MAX_COOKIE_LENGTH) {
      throw invalidCookie();
    }

    int separator = encodedValue.indexOf('.');
    if (separator <= 0 || separator != encodedValue.lastIndexOf('.')) {
      throw invalidCookie();
    }

    try {
      String encodedPayload = encodedValue.substring(0, separator);
      byte[] suppliedSignature = DECODER.decode(encodedValue.substring(separator + 1));
      byte[] expectedSignature = sign(encodedPayload.getBytes(US_ASCII));
      // ASVS V3.2/V6.4: authenticate client-side state and compare MACs in constant time.
      if (!MessageDigest.isEqual(expectedSignature, suppliedSignature)) {
        throw invalidCookie();
      }

      String payload = new String(DECODER.decode(encodedPayload), UTF_8);
      int timestampSeparator = payload.lastIndexOf(':');
      if (timestampSeparator <= 0) {
        throw invalidCookie();
      }
      String username = payload.substring(0, timestampSeparator);
      long issuedAt = Long.parseLong(payload.substring(timestampSeparator + 1));
      long age = Instant.now().getEpochSecond() - issuedAt;
      if (!USERNAME_PATTERN.matcher(username).matches()
          || age < 0
          || age > COOKIE_TTL.toSeconds()) {
        throw invalidCookie();
      }
      return username;
    } catch (IllegalArgumentException exception) {
      throw invalidCookie();
    }
  }

  private static byte[] sign(byte[] payload) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(SIGNING_KEY);
      return mac.doFinal(payload);
    } catch (java.security.InvalidKeyException | NoSuchAlgorithmException exception) {
      throw new IllegalStateException("HMAC-SHA-256 is unavailable", exception);
    }
  }

  private static SecretKeySpec createSigningKey() {
    byte[] key = new byte[KEY_BYTES];
    new SecureRandom().nextBytes(key);
    return new SecretKeySpec(key, "HmacSHA256");
  }

  private static IllegalArgumentException invalidCookie() {
    return new IllegalArgumentException("Invalid authentication cookie");
  }
}
