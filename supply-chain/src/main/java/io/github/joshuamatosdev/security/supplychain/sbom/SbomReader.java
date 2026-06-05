package io.github.joshuamatosdev.security.supplychain.sbom;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Parses a CycloneDX {@code bom.json} into the {@link SbomDocument} projection the integrity gate
 * checks. Missing fields read as {@code null} rather than throwing, so the gate — not the parser —
 * decides what a well-formed bill must contain.
 *
 * <p>Why this exists: SBOM parsing turns generated build evidence into assertions so dependency
 * inventory drift breaks tests instead of reviews.
 */
public final class SbomReader {

  private static final Pattern PACKAGE_URL =
      Pattern.compile(
          "pkg:[a-z][a-z0-9.-]*/[^\\s/?#]+(?:/[^\\s/?#]+)*(?:@[^\\s/?#]+)?(?:\\?[^\\s#]+)?(?:#[^\\s]+)?");
  private static final Pattern QUALIFIER_KEY = Pattern.compile("[a-z][a-z0-9._-]*");
  private static final Pattern SERIAL_NUMBER_UUID =
      Pattern.compile(
          "urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
          Pattern.CASE_INSENSITIVE);
  private static final String COORDINATE_DELIMITERS = "/@?=#&";
  private static final String QUALIFIER_VALUE_DELIMITERS = "/@?=#&";

  private final ObjectMapper mapper =
      JsonMapper.builder()
          .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
          .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .build();

  public SbomDocument read(Path bomJson) {
    try {
      JsonNode root = mapper.readTree(Files.readString(bomJson));
      if (!root.isObject()) {
        throw new IllegalArgumentException("CycloneDX SBOM root must be an object");
      }
      List<SbomDocument.Component> components = new ArrayList<>();
      JsonNode componentNodes = root.path("components");
      if (!componentNodes.isMissingNode() && !componentNodes.isArray()) {
        throw new IllegalArgumentException("CycloneDX components must be an array");
      }
      for (JsonNode component : componentNodes) {
        if (!component.isObject()) {
          throw new IllegalArgumentException("CycloneDX component entries must be objects");
        }
        components.add(
            new SbomDocument.Component(
                text(component, "name"), text(component, "version"), purl(component)));
      }
      return new SbomDocument(
          text(root, "bomFormat"), text(root, "specVersion"), serialNumber(root), components);
    } catch (IOException e) {
      throw new UncheckedIOException("failed to read SBOM at " + bomJson, e);
    }
  }

  private static String text(JsonNode node, String field) {
    JsonNode value = node.get(field);
    if (value == null || value.isNull()) {
      return null;
    }
    if (!value.isTextual()) {
      throw new IllegalArgumentException("CycloneDX field " + field + " must be text when present");
    }
    String text = value.asText();
    if (!text.equals(text.strip())) {
      throw new IllegalArgumentException(
          "CycloneDX field " + field + " must not include leading or trailing whitespace");
    }
    if (text.chars().anyMatch(Character::isISOControl)) {
      throw new IllegalArgumentException(
          "CycloneDX field " + field + " must not contain control characters");
    }
    return text;
  }

  private static String serialNumber(JsonNode node) {
    String serialNumber = text(node, "serialNumber");
    if (serialNumber == null) {
      return null;
    }
    if (!SERIAL_NUMBER_UUID.matcher(serialNumber).matches()) {
      throw new IllegalArgumentException(
          "CycloneDX field serialNumber must be a urn:uuid value when present");
    }
    try {
      UUID.fromString(serialNumber.substring("urn:uuid:".length()));
    } catch (IllegalArgumentException ex) {
      throw new IllegalArgumentException(
          "CycloneDX field serialNumber must be a urn:uuid value when present", ex);
    }
    return serialNumber;
  }

  private static String purl(JsonNode node) {
    String rawPurl = text(node, "purl");
    if (rawPurl == null) {
      return null;
    }
    String purl = canonicalizePackageUrl(rawPurl);
    if (!hasOnlyPackageUrlCharacters(purl)
        || !hasValidPercentEncoding(purl)
        || !hasValidPercentEncodedUtf8(purl)
        || !PACKAGE_URL.matcher(purl).matches()) {
      throw new IllegalArgumentException(
          "CycloneDX field purl must be a package-url value when present");
    }
    if (!hasValidVersionDelimiter(purl)
        || !hasValidCoordinateSeparators(purl)
        || !hasNoPercentEncodedCoordinateDelimiters(purl)
        || !hasValidNamespaceSegments(purl)
        || !hasValidQualifiers(purl)
        || !hasAtMostOneFragmentDelimiter(purl)
        || !hasValidSubpath(purl)) {
      throw new IllegalArgumentException(
          "CycloneDX field purl must be a package-url value when present");
    }
    return purl;
  }

  private static String canonicalizePackageUrl(String purl) {
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

  private static boolean hasValidVersionDelimiter(String purl) {
    String coordinate = coordinate(purl);
    int versionDelimiter = coordinate.indexOf('@');
    if (versionDelimiter < 0) {
      return true;
    }
    int lastPathSeparator = coordinate.lastIndexOf('/');
    return versionDelimiter > 0
        && versionDelimiter < coordinate.length() - 1
        && versionDelimiter > lastPathSeparator + 1
        && coordinate.charAt(versionDelimiter - 1) != '/'
        && coordinate.indexOf('/', versionDelimiter + 1) < 0
        && coordinate.indexOf('@', versionDelimiter + 1) < 0;
  }

  private static boolean hasValidNamespaceSegments(String purl) {
    String coordinate = coordinate(purl);
    int versionDelimiter = coordinate.indexOf('@');
    String coordinatePath =
        versionDelimiter < 0 ? coordinate : coordinate.substring(0, versionDelimiter);
    String[] segments = coordinatePath.split("/", -1);
    for (int index = 0; index < segments.length - 1; index++) {
      if (containsPercentEncodedSlash(segments[index])) {
        return false;
      }
    }
    return true;
  }

  private static boolean hasValidCoordinateSeparators(String purl) {
    String coordinate = coordinate(purl);
    return coordinate.indexOf('=') < 0 && coordinate.indexOf('&') < 0;
  }

  private static boolean hasNoPercentEncodedCoordinateDelimiters(String purl) {
    return !containsPercentEncodedDelimiter(coordinate(purl), COORDINATE_DELIMITERS);
  }

  private static boolean hasOnlyPackageUrlCharacters(String purl) {
    for (int index = 0; index < purl.length(); index++) {
      int character = purl.charAt(index);
      if (isAsciiAlphaNumeric(character)) {
        continue;
      }
      switch (character) {
        case '.', '-', '_', '~', '%', ':', '/', '@', '?', '=', '&', '#' -> {
          continue;
        }
        default -> {
          return false;
        }
      }
    }
    return true;
  }

  private static boolean hasValidPercentEncoding(String purl) {
    for (int index = 0; index < purl.length(); index++) {
      if (purl.charAt(index) != '%') {
        continue;
      }
      if (index + 2 >= purl.length()
          || !isAsciiHexDigit(purl.charAt(index + 1))
          || !isAsciiHexDigit(purl.charAt(index + 2))) {
        return false;
      }
      index += 2;
    }
    return true;
  }

  private static boolean hasValidPercentEncodedUtf8(String purl) {
    ByteArrayOutputStream decoded = new ByteArrayOutputStream(purl.length());
    for (int index = 0; index < purl.length(); index++) {
      char character = purl.charAt(index);
      if (character == '%') {
        decoded.write(Integer.parseInt(purl.substring(index + 1, index + 3), 16));
        index += 2;
      } else {
        decoded.write(character);
      }
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

  private static boolean hasValidQualifiers(String purl) {
    int queryStart = purl.indexOf('?');
    if (queryStart < 0) {
      return true;
    }
    int fragmentStart = purl.indexOf('#', queryStart + 1);
    String qualifiers =
        purl.substring(queryStart + 1, fragmentStart < 0 ? purl.length() : fragmentStart);
    Set<String> keys = new HashSet<>();
    for (String qualifier : qualifiers.split("&", -1)) {
      int separator = qualifier.indexOf('=');
      if (separator <= 0 || separator == qualifier.length() - 1) {
        return false;
      }
      String key = qualifier.substring(0, separator);
      String value = qualifier.substring(separator + 1);
      if (!QUALIFIER_KEY.matcher(key).matches()
          || hasRawQualifierValueDelimiter(value)
          || containsPercentEncodedDelimiter(value, QUALIFIER_VALUE_DELIMITERS)
          || !keys.add(key)) {
        return false;
      }
    }
    return true;
  }

  private static boolean hasRawQualifierValueDelimiter(String value) {
    return value.indexOf('?') >= 0
        || value.indexOf('=') >= 0
        || value.indexOf('/') >= 0
        || value.indexOf('@') >= 0;
  }

  private static boolean hasAtMostOneFragmentDelimiter(String purl) {
    int fragmentStart = purl.indexOf('#');
    return fragmentStart < 0 || purl.indexOf('#', fragmentStart + 1) < 0;
  }

  private static boolean hasValidSubpath(String purl) {
    int fragmentStart = purl.indexOf('#');
    if (fragmentStart < 0) {
      return true;
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

  private static String coordinate(String purl) {
    int coordinateStart = purl.indexOf('/') + 1;
    int coordinateEnd = purl.length();
    int queryStart = purl.indexOf('?');
    if (queryStart >= 0) {
      coordinateEnd = queryStart;
    }
    int fragmentStart = purl.indexOf('#');
    if (fragmentStart >= 0) {
      coordinateEnd = Math.min(coordinateEnd, fragmentStart);
    }
    return purl.substring(coordinateStart, coordinateEnd);
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

  private static boolean isDotSegment(String segment) {
    int dots = 0;
    for (int index = 0; index < segment.length(); ) {
      if (segment.charAt(index) == '.') {
        dots++;
        index++;
      } else if (isPercentEncodedDot(segment, index)) {
        dots++;
        index += 3;
      } else {
        return false;
      }
    }
    return dots == 1 || dots == 2;
  }

  private static boolean isPercentEncodedDot(String value, int index) {
    return index + 2 < value.length()
        && value.charAt(index) == '%'
        && value.charAt(index + 1) == '2'
        && (value.charAt(index + 2) == 'e' || value.charAt(index + 2) == 'E');
  }

  private static boolean containsPercentEncodedSlash(String value) {
    for (int index = 0; index + 2 < value.length(); index++) {
      if (value.charAt(index) == '%'
          && value.charAt(index + 1) == '2'
          && (value.charAt(index + 2) == 'f' || value.charAt(index + 2) == 'F')) {
        return true;
      }
    }
    return false;
  }

  private static boolean containsPercentEncodedDelimiter(String value, String delimiters) {
    for (int index = 0; index + 2 < value.length(); index++) {
      if (value.charAt(index) != '%') {
        continue;
      }
      if (!isAsciiHexDigit(value.charAt(index + 1)) || !isAsciiHexDigit(value.charAt(index + 2))) {
        continue;
      }
      int decoded = Integer.parseInt(value.substring(index + 1, index + 3), 16);
      if (delimiters.indexOf(decoded) >= 0) {
        return true;
      }
      index += 2;
    }
    return false;
  }

  private static boolean isAsciiAlphaNumeric(int character) {
    return character >= 'a' && character <= 'z'
        || character >= 'A' && character <= 'Z'
        || character >= '0' && character <= '9';
  }

  private static boolean isAsciiHexDigit(int character) {
    return character >= 'a' && character <= 'f'
        || character >= 'A' && character <= 'F'
        || character >= '0' && character <= '9';
  }
}
