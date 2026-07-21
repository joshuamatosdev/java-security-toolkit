package io.github.joshuamatosdev.security.supplychain.sbom;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Thin adapter around the package-url reference implementation with strict input validation. */
final class PackageUrls {

  private static final Pattern TYPE = Pattern.compile("[a-z][a-z0-9.-]*");
  private static final Pattern QUALIFIER_KEY = Pattern.compile("[a-z][a-z0-9._-]*");
  private static final String PURL_PUNCTUATION = ".-_~%:/@?=&#";

  private PackageUrls() {}

  static String canonicalize(String purl) {
    // Keep canonicalization lossless. The reference constructor supplies structural validation,
    // but packageurl-java 1.5.0's renderer corrupts non-ASCII octets on current JDKs. Normalize only
    // the scheme/type fields whose representation this boundary controls directly.
    return normalizeSchemeAndType(purl);
  }

  static boolean isValid(String purl) {
    String normalized = normalizeSchemeAndType(purl);
    if (!hasOnlyPermittedCharacters(normalized)
        || !hasValidPercentEncodedUtf8(normalized)
        || !hasValidStructure(normalized)) {
      return false;
    }
    try {
      new PackageURL(normalized);
      return true;
    } catch (MalformedPackageURLException ex) {
      return false;
    }
  }

  private static boolean hasValidStructure(String purl) {
    if (!purl.startsWith("pkg:")) {
      return false;
    }
    int typeEnd = purl.indexOf('/', "pkg:".length());
    if (typeEnd < 0 || !TYPE.matcher(purl.substring("pkg:".length(), typeEnd)).matches()) {
      return false;
    }

    int queryStart = purl.indexOf('?', typeEnd + 1);
    int fragmentStart = purl.indexOf('#', typeEnd + 1);
    if (queryStart >= 0 && fragmentStart >= 0 && queryStart > fragmentStart) {
      return false;
    }
    int coordinateEnd = firstDelimiter(purl.length(), queryStart, fragmentStart);
    String coordinate = purl.substring(typeEnd + 1, coordinateEnd);
    if (!hasValidCoordinates(coordinate)) {
      return false;
    }
    return hasValidQualifiers(purl, queryStart, fragmentStart)
        && hasValidSubpath(purl, fragmentStart);
  }

  private static boolean hasValidCoordinates(String coordinate) {
    if (coordinate.indexOf('=') >= 0 || coordinate.indexOf('&') >= 0) {
      return false;
    }
    int versionDelimiter = coordinate.indexOf('@');
    if (versionDelimiter >= 0
        && (versionDelimiter == 0
            || versionDelimiter == coordinate.length() - 1
            || coordinate.indexOf('@', versionDelimiter + 1) >= 0
            || coordinate.indexOf('/', versionDelimiter + 1) >= 0)) {
      return false;
    }

    String coordinatePath =
        versionDelimiter < 0 ? coordinate : coordinate.substring(0, versionDelimiter);
    coordinatePath = trimSlashes(coordinatePath);
    if (coordinatePath.isEmpty()) {
      return false;
    }
    String[] segments = coordinatePath.split("/", -1);
    for (int index = 0; index < segments.length; index++) {
      if (segments[index].isEmpty()
          || (index < segments.length - 1 && containsPercentEncodedSlash(segments[index]))) {
        return false;
      }
    }
    return true;
  }

  private static boolean hasValidQualifiers(
      String purl, int queryStart, int fragmentStart) {
    if (queryStart < 0) {
      return true;
    }
    int queryEnd = fragmentStart < 0 ? purl.length() : fragmentStart;
    String query = purl.substring(queryStart + 1, queryEnd);
    if (query.isEmpty()) {
      return false;
    }
    Set<String> keys = new HashSet<>();
    for (String qualifier : query.split("&", -1)) {
      int separator = qualifier.indexOf('=');
      if (separator <= 0
          || separator == qualifier.length() - 1
          || qualifier.indexOf('=', separator + 1) >= 0) {
        return false;
      }
      String key = qualifier.substring(0, separator);
      String value = qualifier.substring(separator + 1);
      if (!QUALIFIER_KEY.matcher(key).matches()
          || containsRawQualifierDelimiter(value)
          || !keys.add(key)) {
        return false;
      }
    }
    return true;
  }

  private static boolean containsRawQualifierDelimiter(String value) {
    return value.indexOf('/') >= 0 || value.indexOf('@') >= 0 || value.indexOf('?') >= 0;
  }

  private static boolean hasValidSubpath(String purl, int fragmentStart) {
    if (fragmentStart < 0) {
      return true;
    }
    if (purl.indexOf('#', fragmentStart + 1) >= 0) {
      return false;
    }
    String subpath = trimSlashes(purl.substring(fragmentStart + 1));
    if (subpath.isEmpty()) {
      return false;
    }
    for (String segment : subpath.split("/", -1)) {
      if (segment.isEmpty() || containsPercentEncodedSlash(segment) || isDotSegment(segment)) {
        return false;
      }
    }
    return true;
  }

  private static boolean hasOnlyPermittedCharacters(String purl) {
    for (int index = 0; index < purl.length(); index++) {
      char character = purl.charAt(index);
      if (!(character >= 'a' && character <= 'z')
          && !(character >= 'A' && character <= 'Z')
          && !(character >= '0' && character <= '9')
          && PURL_PUNCTUATION.indexOf(character) < 0) {
        return false;
      }
    }
    return true;
  }

  private static boolean hasValidPercentEncodedUtf8(String purl) {
    ByteArrayOutputStream decoded = new ByteArrayOutputStream(purl.length());
    for (int index = 0; index < purl.length(); index++) {
      char character = purl.charAt(index);
      if (character != '%') {
        decoded.write(character);
        continue;
      }
      if (index + 2 >= purl.length()
          || !isAsciiHexDigit(purl.charAt(index + 1))
          || !isAsciiHexDigit(purl.charAt(index + 2))) {
        return false;
      }
      decoded.write(Integer.parseInt(purl.substring(index + 1, index + 3), 16));
      index += 2;
    }
    try {
      String decodedText =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(decoded.toByteArray()))
              .toString();
      return decodedText.chars().noneMatch(Character::isISOControl);
    } catch (CharacterCodingException ex) {
      return false;
    }
  }

  private static String normalizeSchemeAndType(String purl) {
    if (!purl.regionMatches(true, 0, "pkg:", 0, "pkg:".length())) {
      return purl;
    }
    int typeStart = "pkg:".length();
    while (typeStart < purl.length() && purl.charAt(typeStart) == '/') {
      typeStart++;
    }
    int typeEnd = purl.indexOf('/', typeStart);
    if (typeEnd < 0) {
      return purl;
    }
    return "pkg:"
        + purl.substring(typeStart, typeEnd).toLowerCase(Locale.ROOT)
        + purl.substring(typeEnd);
  }

  private static int firstDelimiter(int fallback, int first, int second) {
    int result = fallback;
    if (first >= 0) {
      result = first;
    }
    if (second >= 0) {
      result = Math.min(result, second);
    }
    return result;
  }

  private static String trimSlashes(String value) {
    int start = 0;
    int end = value.length();
    while (start < end && value.charAt(start) == '/') {
      start++;
    }
    while (end > start && value.charAt(end - 1) == '/') {
      end--;
    }
    return value.substring(start, end);
  }

  private static boolean containsPercentEncodedSlash(String value) {
    return value.toLowerCase(Locale.ROOT).contains("%2f");
  }

  private static boolean isDotSegment(String segment) {
    String decodedDots = segment.toLowerCase(Locale.ROOT).replace("%2e", ".");
    return decodedDots.equals(".") || decodedDots.equals("..");
  }

  private static boolean isAsciiHexDigit(char character) {
    return character >= 'a' && character <= 'f'
        || character >= 'A' && character <= 'F'
        || character >= '0' && character <= '9';
  }
}
