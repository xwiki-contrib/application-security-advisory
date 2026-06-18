/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.securityadvisory.internal;

import java.text.DateFormat;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.xwiki.contrib.securityadvisory.ImpactedPackage;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.extension.ResolveException;
import org.xwiki.extension.repository.ExtensionRepositoryManager;
import org.xwiki.extension.repository.result.CollectionIterableResult;
import org.xwiki.extension.version.Version;
import org.xwiki.extension.version.internal.DefaultVersion;
import org.xwiki.query.Query;
import org.xwiki.query.QueryManager;
import org.xwiki.test.LogLevel;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link VersionReleasedManager}.
 *
 * @version $Id$
 */
@ComponentTest
class VersionReleasedManagerTest
{
    @InjectMockComponents
    private VersionReleasedManager versionReleasedManager;

    @MockComponent
    private SecurityAdvisoryConfiguration configuration;

    @MockComponent
    private QueryManager queryManager;

    @MockComponent
    private ExtensionRepositoryManager extensionRepositoryManager;

    @RegisterExtension
    private LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.WARN);

    private static SecurityAdvisory advisoryWithPackages(ImpactedPackage... packages)
    {
        return new SecurityAdvisory(null).setVulnerablePackages(List.of(packages));
    }

    private static ImpactedPackage impactedPackage(String packageName, String... patchedVersions)
    {
        return new ImpactedPackage(packageName, "maven", List.of(), List.of(patchedVersions));
    }

    @Test
    void computeEmbargoDate() throws ParseException
    {
        Date latestDate = DateFormat
            .getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.FRENCH)
            .parse("22/12/2022 11:00:00");

        when(configuration.getEmbargoDurationUnit()).thenReturn(ChronoUnit.DAYS);
        when(configuration.getDefaultEmbargoDuration()).thenReturn(2L);

        Date expectedDate = DateFormat
            .getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.FRENCH)
            .parse("24/12/2022 11:00:00");
        Date obtainedDate = this.versionReleasedManager.computeEmbargoDate(latestDate);

        assertEquals(expectedDate, obtainedDate);

        when(configuration.getEmbargoDurationUnit()).thenReturn(ChronoUnit.MINUTES);
        when(configuration.getDefaultEmbargoDuration()).thenReturn(10L);

        expectedDate = DateFormat
            .getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.FRENCH)
            .parse("22/12/2022 11:10:00");
        obtainedDate = this.versionReleasedManager.computeEmbargoDate(latestDate);

        assertEquals(expectedDate, obtainedDate);

        when(configuration.getEmbargoDurationUnit()).thenReturn(ChronoUnit.MONTHS);
        when(configuration.getDefaultEmbargoDuration()).thenReturn(1L);

        expectedDate = DateFormat
            .getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.FRENCH)
            .parse("22/01/2023 11:00:00");
        obtainedDate = this.versionReleasedManager.computeEmbargoDate(latestDate);

        assertEquals(expectedDate, obtainedDate);
    }

    @Test
    void computeEmbargoDateForReleasedXWikiProduct() throws Exception
    {
        when(configuration.getEmbargoDurationUnit()).thenReturn(ChronoUnit.DAYS);
        when(configuration.getDefaultEmbargoDuration()).thenReturn(2L);

        // The first version is released later than the second one to make sure the latest date is used.
        Date firstReleaseDate = Date.from(Instant.parse("2024-02-01T10:00:00Z"));
        Date secondReleaseDate = Date.from(Instant.parse("2024-01-01T10:00:00Z"));

        Query releasedQuery = mock(Query.class, "released");
        Query releaseDateQuery = mock(Query.class, "releaseDate");
        when(this.queryManager.createQuery(startsWith("from"), eq(Query.XWQL))).thenReturn(releasedQuery);
        when(this.queryManager.createQuery(startsWith("select"), eq(Query.XWQL))).thenReturn(releaseDateQuery);
        when(releasedQuery.bindValue(anyString(), any())).thenReturn(releasedQuery);
        when(releaseDateQuery.bindValue(anyString(), any())).thenReturn(releaseDateQuery);
        // Both versions are released.
        doReturn(List.of(new Object())).when(releasedQuery).execute();
        doReturn(List.of(firstReleaseDate)).doReturn(List.of(secondReleaseDate)).when(releaseDateQuery).execute();

        SecurityAdvisory advisory =
            advisoryWithPackages(impactedPackage("org.xwiki.platform:xwiki-platform-oldcore", "15.10", "16.4.0"));

        VersionReleasedManager.ComputedEmbargoDate result = this.versionReleasedManager.computeEmbargoDate(advisory);

        assertNotNull(result);
        // The latest release date (firstReleaseDate) plus the 2 days embargo duration.
        assertEquals(Date.from(Instant.parse("2024-02-03T10:00:00Z")), result.embargoDate());
        assertTrue(result.updateExisting());
    }

    @Test
    void computeEmbargoDateForUnreleasedXWikiProduct() throws Exception
    {
        Query releasedQuery = mock(Query.class);
        when(this.queryManager.createQuery(startsWith("from"), eq(Query.XWQL))).thenReturn(releasedQuery);
        when(releasedQuery.bindValue(anyString(), any())).thenReturn(releasedQuery);
        // The version is not released.
        doReturn(List.of()).when(releasedQuery).execute();

        SecurityAdvisory advisory =
            advisoryWithPackages(impactedPackage("org.xwiki.commons:xwiki-commons-component-api", "16.4.0"));

        assertNull(this.versionReleasedManager.computeEmbargoDate(advisory));
    }

    @Test
    void computeEmbargoDateForReleasedExtension() throws Exception
    {
        when(configuration.getEmbargoDurationUnit()).thenReturn(ChronoUnit.DAYS);
        when(configuration.getDefaultEmbargoDuration()).thenReturn(2L);

        List<Version> releasedVersions =
            List.of(new DefaultVersion("1.0"), new DefaultVersion("1.1"), new DefaultVersion("1.2"));
        when(this.extensionRepositoryManager.resolveVersions("org.xwiki.contrib:my-extension", 0, -1))
            .thenReturn(new CollectionIterableResult<>(releasedVersions.size(), 0, releasedVersions));

        SecurityAdvisory advisory =
            advisoryWithPackages(impactedPackage("org.xwiki.contrib:my-extension", "1.2"));

        // Use a one second tolerance around the call window: the manager uses new Date() (millisecond precision)
        // while Instant.now() has a higher precision, so a strict comparison would be flaky.
        Instant beforeCall = Instant.now().minusSeconds(1);
        VersionReleasedManager.ComputedEmbargoDate result = this.versionReleasedManager.computeEmbargoDate(advisory);
        Instant afterCall = Instant.now().plusSeconds(1);

        assertNotNull(result);
        // The release date of an extension is the current date, so the embargo date is "now" plus 2 days. We don't
        // know the exact "now" used internally, so we check that it falls within the call window.
        assertFalse(result.embargoDate().toInstant().isBefore(beforeCall.plus(2, ChronoUnit.DAYS)));
        assertFalse(result.embargoDate().toInstant().isAfter(afterCall.plus(2, ChronoUnit.DAYS)));
        // The embargo date of an extension is based on the current date, so an existing embargo date must not be
        // overwritten.
        assertFalse(result.updateExisting());
    }

    @Test
    void computeEmbargoDateForExtensionWithUnreleasedVersion() throws Exception
    {
        // The repository only knows about 1.0 and 1.1, but the advisory references the (yet unreleased) 1.2.
        List<Version> releasedVersions = List.of(new DefaultVersion("1.0"), new DefaultVersion("1.1"));
        when(this.extensionRepositoryManager.resolveVersions("org.xwiki.contrib:my-extension", 0, -1))
            .thenReturn(new CollectionIterableResult<>(releasedVersions.size(), 0, releasedVersions));

        SecurityAdvisory advisory =
            advisoryWithPackages(impactedPackage("org.xwiki.contrib:my-extension", "1.2"));

        assertNull(this.versionReleasedManager.computeEmbargoDate(advisory));
    }

    @Test
    void computeEmbargoDateForExtensionWithResolveError() throws Exception
    {
        when(this.extensionRepositoryManager.resolveVersions("org.xwiki.contrib:my-extension", 0, -1))
            .thenThrow(new ResolveException("Repository unreachable"));

        SecurityAdvisory advisory =
            advisoryWithPackages(impactedPackage("org.xwiki.contrib:my-extension", "1.2"));

        assertNull(this.versionReleasedManager.computeEmbargoDate(advisory));
        assertEquals(1, this.logCapture.size());
        assertEquals("Error checking if all versions of extension [org.xwiki.contrib:my-extension] are released: "
            + "[ResolveException: Repository unreachable], not computing embargo date", this.logCapture.getMessage(0));
    }

    @Test
    void computeEmbargoDateWithoutVulnerablePackages() throws Exception
    {
        assertNull(this.versionReleasedManager.computeEmbargoDate(advisoryWithPackages()));
    }
}
