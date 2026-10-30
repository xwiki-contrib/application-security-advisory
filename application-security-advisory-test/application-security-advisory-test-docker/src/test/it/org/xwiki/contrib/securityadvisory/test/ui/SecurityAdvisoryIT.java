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
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.securityadvisory.test.po.SecurityAdvisoryEditPage;
import org.xwiki.contrib.securityadvisory.test.po.SecurityAdvisoryHomePage;
import org.xwiki.contrib.securityadvisory.test.po.SecurityAdvisorySchedulerJobs;
import org.xwiki.contrib.securityadvisory.test.po.SecurityAdvisoryViewPage;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.rest.model.jaxb.Object;
import org.xwiki.test.docker.junit5.TestReference;
import org.xwiki.test.docker.junit5.UITest;
import org.xwiki.test.ui.TestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.xwiki.contrib.securityadvisory.SecurityAdvisory.State.ANNOUNCED;
import static org.xwiki.contrib.securityadvisory.SecurityAdvisory.State.COMPLETED;
import static org.xwiki.contrib.securityadvisory.SecurityAdvisory.State.DISCLOSABLE;
import static org.xwiki.contrib.securityadvisory.SecurityAdvisory.State.DRAFT;
import static org.xwiki.test.ui.TestUtils.RestTestUtils.property;

/**
 * Functional tests of the lifecycle of an advisory: creation, announce, release of its patched versions, computation of
 * its embargo date and switch to disclosable once that date is reached.
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

    private static final String FIRST_PATCHED_VERSION = "42.1.1";

    private static final String LAST_PATCHED_VERSION = "42.2.0";

    /**
     * Released more than {@link #EMBARGO_DAYS} ago, so that the embargo of the advisory is over once computed.
     */
    private static final LocalDate FIRST_RELEASE_DATE = LocalDate.of(2020, 1, 10);

    private static final LocalDate LAST_RELEASE_DATE = LocalDate.of(2020, 3, 15);

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
        editPage.setTitle("Remote code execution in the test module");
        editPage.setComputeEmbargoDate(true);
        SecurityAdvisoryViewPage advisoryPage = editPage.save();
        assertEquals("Remote code execution in the test module", advisoryPage.getDocumentTitle());
        assertEquals(DRAFT, advisoryPage.getStatus());
        advisoryReference = advisoryPage.getAdvisoryReference();

        // No UI allows to add the impacted packages: they are imported along with the advisory from GitHub.
        addImpactedPackage(setup, advisoryReference, FIRST_PATCHED_VERSION, LAST_PATCHED_VERSION);

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
        setup.rest().savePage(recentAdvisoryReference, "", "Recently patched advisory");
        Object recentAdvisory = setup.rest().object(recentAdvisoryReference, SecurityAdvisoryViewPage.ADVISORY_CLASS);
        recentAdvisory.withProperties(property("status", ANNOUNCED.name()), property("computeEmbargo", 1));
        setup.rest().add(recentAdvisory);
        addImpactedPackage(setup, recentAdvisoryReference, recentPatchedVersion);
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

    private static void addImpactedPackage(TestUtils setup, DocumentReference advisory, String... patchedVersions)
        throws Exception
    {
        Object impactedPackage = setup.rest().object(advisory, SecurityAdvisoryViewPage.IMPACTED_PACKAGE_CLASS);
        impactedPackage.withProperties(property("ecosystem", "maven"), property("packageId", PACKAGE_ID),
            property("patchedVersions", String.join("|", patchedVersions)));
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
