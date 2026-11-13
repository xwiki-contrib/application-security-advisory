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
package org.xwiki.contrib.securityadvisory.test.ui;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.securityadvisory.test.po.SecurityAdvisoryEditPage;
import org.xwiki.contrib.securityadvisory.test.po.SecurityAdvisoryHomePage;
import org.xwiki.contrib.securityadvisory.test.po.SecurityAdvisoryHomePage.ImpactedPackage;
import org.xwiki.contrib.securityadvisory.test.po.SecurityAdvisorySchedulerJobs;
import org.xwiki.contrib.securityadvisory.test.po.SecurityAdvisoryViewPage;
import org.xwiki.livedata.test.po.TableLayoutElement;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.rest.model.jaxb.Object;
import org.xwiki.test.docker.junit5.TestReference;
import org.xwiki.test.docker.junit5.UITest;
import org.xwiki.test.ui.TestUtils;
import org.xwiki.test.ui.po.ViewPage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.xwiki.contrib.securityadvisory.SecurityAdvisory.State.ANNOUNCED;
import static org.xwiki.contrib.securityadvisory.SecurityAdvisory.State.COMPLETED;
import static org.xwiki.contrib.securityadvisory.SecurityAdvisory.State.DISCLOSABLE;
import static org.xwiki.contrib.securityadvisory.SecurityAdvisory.State.DISCLOSED;
import static org.xwiki.contrib.securityadvisory.SecurityAdvisory.State.DRAFT;
import static org.xwiki.test.ui.TestUtils.RestTestUtils.property;

/**
 * Functional tests of the lifecycle of an advisory: creation, announce, release of its patched versions, computation of
 * its embargo date, switch to disclosable once that date is reached, and disclosure.
 *
 * @version $Id$
 */
@UITest(
    properties = {
        // The Scheduler home page, from which the scheduler jobs of the application are triggered, needs programming
        // rights to list and trigger the jobs.
        "xwikiPropertiesAdditionalProperties=test.prchecker.excludePattern=xwiki:Scheduler\\.WebHome",
        // Add the Scheduler plugin, which runs the scheduler jobs of the application.
        "xwikiCfgPlugins=com.xpn.xwiki.plugin.skinx.JsSkinExtensionPlugin,"
            + "com.xpn.xwiki.plugin.skinx.JsSkinFileExtensionPlugin,"
            + "com.xpn.xwiki.plugin.skinx.CssSkinExtensionPlugin,"
            + "com.xpn.xwiki.plugin.skinx.CssSkinFileExtensionPlugin,"
            + "com.xpn.xwiki.plugin.skinx.LinkExtensionPlugin,"
            + "com.xpn.xwiki.plugin.scheduler.SchedulerPlugin"
    },
    extraJARs = {
        // The Scheduler plugin needs to be in WEB-INF/lib since it's defined in xwiki.cfg and plugins are loaded by
        // XWiki at startup, i.e. before extensions are provisioned for the tests.
        "org.xwiki.platform:xwiki-platform-scheduler-api"
    },
    resolveExtraJARs = true
)
class SecurityAdvisoryIT
{
    private static final String RELEASE_NOTE_CLASS = "ReleaseNotes.Code.ReleaseNoteClass";

    private static final DateTimeFormatter RELEASE_DATE_FORMAT = DateTimeFormatter.ofPattern("dd/MM/yyyy");

    /**
     * The embargo duration configured by default: 90 days after the release of the last patched version.
     */
    private static final int EMBARGO_DAYS = 90;

    /**
     * The release of XWiki core modules are looked for in the release notes of the XWiki product, and only there.
     */
    private static final String PRODUCT = "XWiki";

    private static final String PACKAGE_ID = "org.xwiki.platform:xwiki-platform-security-advisory-test";

    /**
     * A second package impacted by the advisory, patched in the last patched version only.
     */
    private static final String SECOND_PACKAGE_ID = "org.xwiki.platform:xwiki-platform-security-advisory-other-test";

    private static final List<String> AFFECTED_RANGES = List.of("[1.0,42.1.1)", "[42.2.0-rc-1,42.2.0)");

    private static final List<String> SECOND_PACKAGE_AFFECTED_RANGES = List.of("[1.0,42.2.0)");

    private static final String FIRST_PATCHED_VERSION = "42.1.1";

    private static final String LAST_PATCHED_VERSION = "42.2.0";

    /**
     * Released more than {@link #EMBARGO_DAYS} ago, so that the embargo of the advisory is over once computed.
     */
    private static final LocalDate FIRST_RELEASE_DATE = LocalDate.of(2020, 1, 10);

    private static final LocalDate LAST_RELEASE_DATE = LocalDate.of(2020, 3, 15);

    private static final String ADVISORY_TITLE = "Remote code execution in the test module";

    private static final String RECENT_ADVISORY_TITLE = "Recently patched advisory";

    private static final String TITLE_COLUMN = "Page Title";

    private static final String STATUS_COLUMN = "status";

    /**
     * The advisory created by the first test and followed by the next ones.
     */
    private static DocumentReference advisoryReference;

    @Test
    @Order(1)
    void createAndAnnounceAdvisory(TestUtils setup) throws Exception
    {
        setup.loginAsSuperAdmin();

        SecurityAdvisoryEditPage editPage = SecurityAdvisoryHomePage.gotoPage().clickAddAdvisory();
        editPage.setTitle(ADVISORY_TITLE);
        editPage.setComputeEmbargoDate(true);
        SecurityAdvisoryViewPage advisoryPage = editPage.save();
        assertEquals(ADVISORY_TITLE, advisoryPage.getDocumentTitle());
        assertEquals(DRAFT, advisoryPage.getStatus());
        advisoryReference = advisoryPage.getAdvisoryReference();

        // No UI allows to add the impacted packages: they are imported along with the advisory from GitHub.
        addImpactedPackage(setup, advisoryReference, PACKAGE_ID, AFFECTED_RANGES, FIRST_PATCHED_VERSION,
            LAST_PATCHED_VERSION);
        addImpactedPackage(setup, advisoryReference, SECOND_PACKAGE_ID, SECOND_PACKAGE_AFFECTED_RANGES,
            LAST_PATCHED_VERSION);

        advisoryPage = SecurityAdvisoryViewPage.gotoPage(advisoryReference);
        assertEquals(Map.of(FIRST_PATCHED_VERSION, false, LAST_PATCHED_VERSION, false),
            advisoryPage.getPatchedVersions(PACKAGE_ID));
        assertEquals(Optional.empty(), advisoryPage.getEmbargoDate());

        advisoryPage = advisoryPage.markCompleted();
        assertEquals(COMPLETED, advisoryPage.getStatus());

        advisoryPage = advisoryPage.markAnnounced();
        assertEquals(ANNOUNCED, advisoryPage.getStatus());
        // The patched versions are not released yet.
        assertEquals(Optional.empty(), advisoryPage.getEmbargoDate());
    }

    @Test
    @Order(2)
    void releasePatchedVersions(TestUtils setup, TestReference testReference) throws Exception
    {
        DocumentReference firstReleaseNote = createReleaseNote(setup, testReference, FIRST_PATCHED_VERSION);
        DocumentReference lastReleaseNote = createReleaseNote(setup, testReference, LAST_PATCHED_VERSION);

        release(setup, firstReleaseNote, FIRST_RELEASE_DATE);
        SecurityAdvisoryViewPage advisoryPage = SecurityAdvisoryViewPage.gotoPage(advisoryReference);
        assertEquals(Map.of(FIRST_PATCHED_VERSION, true, LAST_PATCHED_VERSION, false),
            advisoryPage.getPatchedVersions(PACKAGE_ID));
        // The embargo date is computed only once all the patched versions are released.
        assertEquals(Optional.empty(), advisoryPage.getEmbargoDate());

        release(setup, lastReleaseNote, LAST_RELEASE_DATE);
        advisoryPage = SecurityAdvisoryViewPage.gotoPage(advisoryReference);
        assertEquals(Map.of(FIRST_PATCHED_VERSION, true, LAST_PATCHED_VERSION, true),
            advisoryPage.getPatchedVersions(PACKAGE_ID));
        // The embargo starts with the release of the last patched version.
        assertEquals(Optional.of(LAST_RELEASE_DATE.plusDays(EMBARGO_DAYS)), advisoryPage.getEmbargoDate());
        // Even though the embargo date is already reached, the advisory is marked disclosable only by the scheduler.
        assertEquals(ANNOUNCED, advisoryPage.getStatus());
        assertFalse(advisoryPage.canMarkDisclosed());
    }

    @Test
    @Order(3)
    void markDisclosableOnceEmbargoDateIsReached(TestUtils setup, TestReference testReference) throws Exception
    {
        // A second announced advisory, whose patched version is released today, so that its embargo date is not
        // reached yet.
        String recentPatchedVersion = "42.3.0";
        LocalDate recentReleaseDate = LocalDate.now();
        DocumentReference recentAdvisoryReference =
            new DocumentReference("RecentAdvisory", testReference.getLastSpaceReference());
        setup.rest().savePage(recentAdvisoryReference, "", RECENT_ADVISORY_TITLE);
        Object recentAdvisory = setup.rest().object(recentAdvisoryReference, SecurityAdvisoryViewPage.ADVISORY_CLASS);
        recentAdvisory.withProperties(property("status", ANNOUNCED.name()), property("computeEmbargo", 1));
        setup.rest().add(recentAdvisory);
        addImpactedPackage(setup, recentAdvisoryReference, PACKAGE_ID, List.of(), recentPatchedVersion);
        release(setup, createReleaseNote(setup, testReference, recentPatchedVersion), recentReleaseDate);

        new SecurityAdvisorySchedulerJobs().triggerDisclosableComputation();

        SecurityAdvisoryViewPage advisoryPage =
            SecurityAdvisoryViewPage.gotoPage(advisoryReference).reloadUntilStatus(DISCLOSABLE);
        assertTrue(advisoryPage.canMarkDisclosed());

        advisoryPage = SecurityAdvisoryViewPage.gotoPage(recentAdvisoryReference);
        assertEquals(Optional.of(recentReleaseDate.plusDays(EMBARGO_DAYS)), advisoryPage.getEmbargoDate());
        assertEquals(ANNOUNCED, advisoryPage.getStatus());
        assertFalse(advisoryPage.canMarkDisclosed());
    }

    @Test
    @Order(4)
    void discloseAdvisory()
    {
        SecurityAdvisoryViewPage advisoryPage = SecurityAdvisoryViewPage.gotoPage(advisoryReference).markDisclosed();
        assertEquals(ADVISORY_TITLE, advisoryPage.getDocumentTitle());
        assertEquals(DISCLOSED, advisoryPage.getStatus());
        assertEquals(new SpaceReference("xwiki", "SecurityAdvisoryApplication", "DisclosedEntries"),
            advisoryPage.getAdvisoryReference().getLastSpaceReference());

        // The home page lists only the disclosed advisories by default, and not the recent one, which is announced. The
        // default status filter is displayed in the status column, so that it can be removed from there.
        SecurityAdvisoryHomePage homePage = SecurityAdvisoryHomePage.gotoPage();
        TableLayoutElement tableLayout = homePage.getAdvisories().getTableLayout();
        assertEquals(1, tableLayout.countRows());
        tableLayout.assertRow(TITLE_COLUMN, ADVISORY_TITLE);
        assertEquals(List.of("disclosed"), tableLayout.getFilterValues(STATUS_COLUMN));
        // The row of the advisory lists all its impacted packages, each with its affected version ranges and its
        // patched versions, and the patched versions of all its packages, each version once.
        assertEquals(List.of(
            new ImpactedPackage(PACKAGE_ID, AFFECTED_RANGES, List.of(FIRST_PATCHED_VERSION, LAST_PATCHED_VERSION)),
            new ImpactedPackage(SECOND_PACKAGE_ID, SECOND_PACKAGE_AFFECTED_RANGES, List.of(LAST_PATCHED_VERSION))),
            homePage.getImpactedPackages(1));
        assertEquals(List.of(FIRST_PATCHED_VERSION, LAST_PATCHED_VERSION), homePage.getPatchedVersions(1));

        // Without the status filter, the other advisories are listed too, while the page holding the advisory before
        // its disclosure, which now redirects to the published page, is not.
        homePage.removeAdvisoriesColumnFilter(STATUS_COLUMN);
        tableLayout.waitUntilRowCountEqualsTo(2);
        assertEquals(List.of(), tableLayout.getFilterValues(STATUS_COLUMN));
        tableLayout.assertRow(TITLE_COLUMN, ADVISORY_TITLE);
        tableLayout.assertRow(TITLE_COLUMN, RECENT_ADVISORY_TITLE);

        // Filtering on its second impacted package, which is not impacted by the recent advisory, lists back only the
        // disclosed advisory.
        homePage.filterAdvisoriesByPackage(SECOND_PACKAGE_ID);
        tableLayout.waitUntilRowCountEqualsTo(1);
        tableLayout.assertRow(TITLE_COLUMN, ADVISORY_TITLE);
    }

    @Test
    @Order(5)
    void warnAboutSecurityEntriesOpenToAllUsers()
    {
        // No right restricts the access to the advisories on the test instance, so the home page warns about it, with a
        // link to the rights editor of their space.
        SecurityAdvisoryHomePage homePage = SecurityAdvisoryHomePage.gotoPage();
        assertTrue(homePage.hasSecurityEntriesAccessWarning());

        homePage.clickSecurityEntriesAccessWarningLink().getRightsTable();
        ViewPage rightsPage = new ViewPage();
        assertEquals("admin", rightsPage.getMetaDataValue("action"));
        assertEquals("SecurityAdvisoryApplication.SecurityEntries", rightsPage.getMetaDataValue("space"));
    }

    private static void addImpactedPackage(TestUtils setup, DocumentReference advisory, String packageId,
        List<String> affectedRanges, String... patchedVersions) throws Exception
    {
        // The commas of the version ranges are escaped, since they also separate the values of the list properties.
        String ranges =
            affectedRanges.stream().map(range -> range.replace(",", "\\,")).collect(Collectors.joining("|"));
        Object impactedPackage = setup.rest().object(advisory, SecurityAdvisoryViewPage.IMPACTED_PACKAGE_CLASS);
        impactedPackage.withProperties(property("ecosystem", "maven"), property("packageId", packageId),
            property("vulnerableVersionRange", ranges), property("patchedVersions", String.join("|", patchedVersions)));
        setup.rest().add(impactedPackage);
    }

    /**
     * Create the release note of a version that is not released yet.
     */
    private static DocumentReference createReleaseNote(TestUtils setup, TestReference testReference, String version)
        throws Exception
    {
        DocumentReference releaseNote =
            new DocumentReference("ReleaseNote " + version, testReference.getLastSpaceReference());
        setup.rest().savePage(releaseNote, "", PRODUCT + " " + version);
        Object releaseNoteObject = setup.rest().object(releaseNote, RELEASE_NOTE_CLASS);
        releaseNoteObject.withProperties(property("product", PRODUCT), property("version", version),
            property("released", 0));
        setup.rest().add(releaseNoteObject);
        return releaseNote;
    }

    /**
     * Mark the version of the given release note as released, which is what the advisories listen to.
     */
    private static void release(TestUtils setup, DocumentReference releaseNote, LocalDate releaseDate)
        throws Exception
    {
        Object releaseNoteObject = setup.rest().object(releaseNote, RELEASE_NOTE_CLASS);
        releaseNoteObject.withProperties(property("released", 1),
            property("date", releaseDate.format(RELEASE_DATE_FORMAT)));
        setup.rest().update(releaseNoteObject);
    }
}
