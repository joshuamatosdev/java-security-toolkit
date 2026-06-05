package io.github.joshuamatosdev.security.tenant.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Build-breaking guard for the "database owns UUID creation" invariant.
 *
 * <p>Primary keys are minted by the PostgreSQL 18 {@code id_v7} domain default ({@code uuidv7()});
 * application code never generates an identifier. Three rules keep that contract honest in
 * production Java ({@code src/main/java}):
 *
 * <ol>
 *   <li>no client-side UUID creation ({@code UUID.randomUUID()} and friends),
 *   <li>no UUID-creation SQL function assembled in application Java,
 *   <li>no Hibernate {@code @UuidGenerator} — it mints a client-side v4 before INSERT, pre-empting
 *       the column default and breaking the v7 ordering contract.
 * </ol>
 *
 * <p>Test code may mint UUIDs freely (deterministic fixtures); only {@code src/main/java} is scanned.
 * See the module README for the rationale. Ceiling is zero — there is no allowlist.
 *
 * <p>Why this is important to test: static audits catch future code that moves UUID ownership or
 * signed-claim verification out of the database boundary.
 */
class DatabaseOwnsUuidCreationArchTest {

    private static final Path PRODUCTION_SOURCES = Path.of("src/main/java");

    private static final Pattern BANNED_JAVA_UUID_CREATION = Pattern.compile("\\bUUID\\s*\\.\\s*randomUUID\\s*\\("
            + "|\\bUUID\\s*\\.\\s*nameUUIDFromBytes\\s*\\("
            + "|\\bnew\\s+UUID\\s*\\("
            + "|\\bGenerators\\s*\\.\\s*timeBasedEpochGenerator\\s*\\("
            + "|\\bGenerators\\s*\\.\\s*timeBasedGenerator\\s*\\("
            + "|\\bGenerators\\s*\\.\\s*randomBasedGenerator\\s*\\(");

    private static final Pattern BANNED_SQL_UUID_FUNCTION =
            Pattern.compile("\\b(gen_random_uuid|uuidv7|uuid_generate_v\\d+)\\s*\\(", Pattern.CASE_INSENSITIVE);

    private static final Pattern BANNED_HIBERNATE_UUID_GENERATOR =
            Pattern.compile("@\\s*(?:org\\s*\\.\\s*hibernate\\s*\\.\\s*annotations\\s*\\.\\s*)?UuidGenerator\\b");

    private static final Pattern LINE_COMMENT = Pattern.compile("//[^\\n]*");
    private static final Pattern BLOCK_COMMENT = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);

    private static final String JAVA_FAILURE_HEADER =
        """
            Application code must not create UUIDs — the database owns UUID creation (PG18 id_v7 domain,
              DEFAULT uuidv7()).
            Banned primitives: UUID.randomUUID(), UUID.nameUUIDFromBytes(), new UUID(long, long),
              Generators.timeBasedEpochGenerator(), Generators.timeBasedGenerator(),
              Generators.randomBasedGenerator().
            Fix: declare the @Id column insertable = false with
              @org.hibernate.annotations.Generated(event = EventType.INSERT) so Hibernate reads the
              DB-assigned key back via RETURNING; the id_v7 domain carries the DEFAULT that mints it.
            Allowed: UUID.fromString(...) for parsing; the UUID type as a field/return type; minting
              UUIDs in test code (src/test/java). Ceiling = 0. No allowlist. Violations:""";

    private static final String SQL_FAILURE_HEADER =
        """
            Application Java must not invoke UUID-creation SQL functions imperatively
              (gen_random_uuid(...), uuidv7(...), uuid_generate_vN(...)).
            Fix: move the function to a column DEFAULT in the schema DDL
              (src/test/resources/db/init.sql here, the schema authority). The database fires the
              default at INSERT; the application omits the id column and reads the value back.
            Ceiling = 0. No allowlist. Violations:""";

    private static final String HIBERNATE_GENERATOR_FAILURE_HEADER =
        """
            JPA entities must not use Hibernate's @UuidGenerator annotation.
              It generates a UUID in Java before INSERT, pre-emptying the column's DEFAULT uuidv7()
              with a v4 (RANDOM) UUID and defeating the id_v7 ordering contract. @UuidGenerator(style =
              TIME) is also client-side and equally banned: identity issuance is the database's job.
            Fix: drop @UuidGenerator and its import; declare the @Id column insertable = false with
              @org.hibernate.annotations.Generated(event = EventType.INSERT). Ceiling = 0. Violations:""";

    @Test
    @DisplayName("Application code must not create UUIDs — UUID generation belongs to the database")
    void applicationCodeMustNotCreateUuids() throws IOException {
        assertThat(scanProductionJava(BANNED_JAVA_UUID_CREATION)).as(JAVA_FAILURE_HEADER).isEmpty();
    }

    @Test
    @DisplayName("Application Java must not invoke gen_random_uuid / uuidv7 / uuid_generate_vN")
    void applicationJavaMustNotInvokeDatabaseUuidFunctions() throws IOException {
        assertThat(scanProductionJava(BANNED_SQL_UUID_FUNCTION)).as(SQL_FAILURE_HEADER).isEmpty();
    }

    @Test
    @DisplayName("Entities must not use Hibernate's @UuidGenerator — the database owns UUID issuance")
    void entitiesMustNotUseHibernateUuidGenerator() throws IOException {
        assertThat(scanProductionJava(BANNED_HIBERNATE_UUID_GENERATOR))
                .as(HIBERNATE_GENERATOR_FAILURE_HEADER)
                .isEmpty();
    }

    private static List<String> scanProductionJava(final Pattern banned) throws IOException {
        final List<String> violations = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(PRODUCTION_SOURCES)) {
            paths.filter(path -> path.toString().endsWith(".java")).forEach(path -> {
                try {
                    final String raw = Files.readString(path);
                    final String stripped = BLOCK_COMMENT.matcher(raw).replaceAll("");
                    final String codeOnly = LINE_COMMENT.matcher(stripped).replaceAll("");
                    final Matcher matcher = banned.matcher(codeOnly);
                    while (matcher.find()) {
                        violations.add(path.toString().replace('\\', '/')
                                + ":" + lineOfOffset(codeOnly, matcher.start())
                                + " — banned token '" + matcher.group() + "'");
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        }
        return violations;
    }

    private static int lineOfOffset(final String text, final int offset) {
        int line = 1;
        for (int i = 0; i < offset && i < text.length(); i++) {
            if (text.charAt(i) == '\n') {
                line++;
            }
        }
        return line;
    }
}
