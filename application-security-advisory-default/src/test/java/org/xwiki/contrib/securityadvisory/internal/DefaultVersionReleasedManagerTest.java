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
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.xwiki.contrib.securityadvisory.ImpactedPackage;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.VersionReleasedManager;
import org.xwiki.extension.ExtensionId;
import org.xwiki.extension.repository.ExtensionRepositoryManager;
import org.xwiki.query.Query;
import org.xwiki.query.QueryManager;
import org.xwiki.test.LogLevel;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link VersionReleasedManager}.
 *
 * @version $Id$
 */
@ComponentTest
class DefaultVersionReleasedManagerTest
{
    @InjectMockComponents
    private DefaultVersionReleasedManager versionReleasedManager;

    @MockComponent
    private SecurityAdvisoryConfiguration configuration;

    @MockComponent
    private QueryManager queryManager;

    @MockComponent
    private ExtensionRepositoryManager extensionRepositoryManager;

    @RegisterExtension
    private LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.WARN);

    private static SecurityAdvisory advisoryWithPackages(String productName, ImpactedPackage... packages)
    {
        return new SecurityAdvisory(null).setProduct(productName).setVulnerablePackages(List.of(packages));
    }

    private static ImpactedPackage impactedPackage(String packageName, String... patchedVersions)
    {
        return new ImpactedPackage("maven", packageName, List.of(), List.of(patchedVersions), List.of(),
            Optional.empty());
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
    void updateReleasedVersionsForReleasedXWikiProduct() throws Exception
    {
        when(configuration.getEmbargoDurationUnit()).thenReturn(ChronoUnit.DAYS);
        when(configuration.getDefaultEmbargoDuration()).thenReturn(2L);
        String productName = "foo";

        // The first version is released later than the second one to make sure the latest date is used.
        Date firstReleaseDate = Date.from(Instant.parse("2024-02-01T10:00:00Z"));
        Date secondReleaseDate = Date.from(Instant.parse("2024-01-01T10:00:00Z"));

        Query releaseDateQuery = mock(Query.class, "releaseDate");
        when(this.queryManager.createQuery(startsWith("select"), eq(Query.XWQL))).thenReturn(releaseDateQuery);
        when(releaseDateQuery.bindValue(anyString(), any())).thenReturn(releaseDateQuery);
        // Both versions are released.
        doReturn(List.of(firstReleaseDate)).doReturn(List.of(secondReleaseDate)).when(releaseDateQuery).execute();

        SecurityAdvisory advisory =
            advisoryWithPackages(productName,
                impactedPackage("org.xwiki.platform:xwiki-platform-oldcore", "15.10", "16.4.0"));
        assertTrue(this.versionReleasedManager.updateReleasedVersions(advisory));

        assertEquals(firstReleaseDate,
            advisory.getVulnerablePackages().get(0).dateOfLatestRelease().get());
        assertEquals(List.of("15.10", "16.4.0"), advisory.getVulnerablePackages().get(0).releasedVersions());
        verify(releaseDateQuery, times(2)).bindValue(anyString(), eq("XWiki"));
        verify(releaseDateQuery).bindValue(anyString(), eq("15.10"));
        verify(releaseDateQuery).bindValue(anyString(), eq("16.4.0"));
    }

    @Test
    void updateReleasedVersionsForUnreleasedXWikiProduct() throws Exception
    {
        String productName = "foo";
        Query releaseDateQuery = mock(Query.class, "releaseDate");
        when(this.queryManager.createQuery(startsWith("select"), eq(Query.XWQL))).thenReturn(releaseDateQuery);
        when(releaseDateQuery.bindValue(anyString(), any())).thenReturn(releaseDateQuery);
        // The version is not released.
        doReturn(List.of()).when(releaseDateQuery).execute();

        SecurityAdvisory advisory =
            advisoryWithPackages(productName,
                impactedPackage("org.xwiki.commons:xwiki-commons-component-api", "16.4.0"));

        assertFalse(this.versionReleasedManager.updateReleasedVersions(advisory));
        assertEquals(Optional.empty(), advisory.getVulnerablePackages().get(0).dateOfLatestRelease());
        assertEquals(List.of(), advisory.getVulnerablePackages().get(0).releasedVersions());
    }

    @Test
    void updateReleasedVersionsForExtensions() throws Exception
    {
        String productName = "foo";
        Query releaseDateQuery = mock(Query.class, "releaseDate");
        when(this.queryManager.createQuery(startsWith("select"), eq(Query.XWQL))).thenReturn(releaseDateQuery);
        when(releaseDateQuery.bindValue(anyString(), any())).thenReturn(releaseDateQuery);
        // The version is not released.
        doReturn(List.of()).when(releaseDateQuery).execute();

        // The repository knows about 1.1, but the advisory also references the (yet unreleased) 1.2.
        when(this.extensionRepositoryManager.exists(new ExtensionId("org.xwiki.contrib:my-extension", "1.1")))
            .thenReturn(true);
        when(this.extensionRepositoryManager.exists(new ExtensionId("org.xwiki.contrib:my-extension", "1.2")))
            .thenReturn(false);

        SecurityAdvisory advisory = advisoryWithPackages(productName,
            impactedPackage("org.xwiki.contrib:my-extension", "1.1", "1.2"));

        // Use a one second tolerance around the call window: the manager uses new Date() (millisecond precision)
        // while Instant.now() has a higher precision, so a strict comparison would be flaky.
        Instant beforeCall = Instant.now().minusSeconds(1);
        assertTrue(this.versionReleasedManager.updateReleasedVersions(advisory));
        Instant afterCall = Instant.now().plusSeconds(1);

        ImpactedPackage impactedPackage = advisory.getVulnerablePackages().get(0);
        Optional<Date> dateOfLatestRelease = impactedPackage.dateOfLatestRelease();
        assertTrue(dateOfLatestRelease.isPresent());
        assertTrue(dateOfLatestRelease.get().toInstant().isAfter(beforeCall));
        assertTrue(dateOfLatestRelease.get().toInstant().isBefore(afterCall));
        // The embargo date of an extension is based on the current date, so an existing embargo date must not be
        // overwritten.
        assertEquals(List.of("1.1"), impactedPackage.releasedVersions());
        assertEquals(List.of("1.1", "1.2"), impactedPackage.patchedVersions());
        assertEquals("maven", impactedPackage.ecosystem());
        assertEquals("org.xwiki.contrib:my-extension", impactedPackage.packageName());

        assertFalse(versionReleasedManager.updateReleasedVersions(advisory));
    }

    @Test
    void updateReleasedVersionsUnsupportedPackage() throws Exception
    {
        ImpactedPackage impactedPackage = new ImpactedPackage("npm", "foo", List.of(), List.of("2.1"), List.of(),
            Optional.empty());
        assertFalse(this.versionReleasedManager.updateReleasedVersions(advisoryWithPackages("foo", impactedPackage)));
        assertEquals("Impossible to test if [foo] has been released: [npm] ecosystem is not supported.",
            logCapture.getMessage(0));

    }

    @Test
    void getEmbargoDate() throws Exception
    {
        when(configuration.getEmbargoDurationUnit()).thenReturn(ChronoUnit.DAYS);
        when(configuration.getDefaultEmbargoDuration()).thenReturn(2L);

        assertTrue(this.versionReleasedManager.getEmbargoDate(advisoryWithPackages("foo")).isEmpty());

        ImpactedPackage impactedPackage1 = mock(ImpactedPackage.class, "package1");
        when(impactedPackage1.patchedVersions()).thenReturn(List.of("1.1"));
        when(impactedPackage1.releasedVersions()).thenReturn(List.of("1.1"));
        when(impactedPackage1.dateOfLatestRelease())
            .thenReturn(Optional.of(Date.from(Instant.parse("2024-02-01T10:00:00Z"))));

        ImpactedPackage impactedPackage2 = mock(ImpactedPackage.class, "package2");
        when(impactedPackage2.dateOfLatestRelease()).thenReturn(Optional.empty());

        ImpactedPackage impactedPackage3 = mock(ImpactedPackage.class, "package3");
        when(impactedPackage3.patchedVersions()).thenReturn(List.of("1.2", "2.3"));
        when(impactedPackage3.releasedVersions()).thenReturn(List.of("2.3"));
        when(impactedPackage3.dateOfLatestRelease())
            .thenReturn(Optional.of(Date.from(Instant.parse("2024-01-01T10:00:00Z"))));

        SecurityAdvisory securityAdvisory =
            advisoryWithPackages("foo", impactedPackage1, impactedPackage2, impactedPackage3);
        assertTrue(this.versionReleasedManager.getEmbargoDate(securityAdvisory).isEmpty());

        when(impactedPackage2.dateOfLatestRelease())
            .thenReturn(Optional.of(Date.from(Instant.parse("2024-03-01T10:00:00Z"))));
        assertTrue(this.versionReleasedManager.getEmbargoDate(securityAdvisory).isEmpty());

        when(impactedPackage3.releasedVersions()).thenReturn(List.of("1.2", "2.3"));
        Optional<Date> embargoDate = this.versionReleasedManager.getEmbargoDate(securityAdvisory);
        assertTrue(embargoDate.isPresent());
        assertEquals(Date.from(Instant.parse("2024-02-03T10:00:00Z")), embargoDate.get());
    }
}
