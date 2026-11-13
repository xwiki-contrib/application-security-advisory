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

import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.xwiki.contrib.securityadvisory.AdvisoryImporter;
import org.xwiki.contrib.securityadvisory.ExternalUser;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoriesManager;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.internal.assignee.ExternalUserClassMandatoryDocumentInitializer;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryManager;
import org.xwiki.test.LogLevel;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link SecurityAdvisoryDataMigrator}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class SecurityAdvisoryDataMigratorTest
{
    private static final List<String> ENTRIES_SPACE = List.of("SecurityAdvisoryApplication", "SecurityEntries");

    private static final List<String> PUBLIC_SPACE = List.of("SecurityAdvisoryApplication", "DisclosedEntries");

    private static final String ADVISORY_LINK =
        "https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-8469-jx93-r677";

    private static final List<ExternalUser> EXTERNAL_USERS = List.of(new ExternalUser("github", "42", "reporter"));

    @InjectMockComponents
    private SecurityAdvisoryDataMigrator migrator;

    @MockComponent
    private QueryManager queryManager;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @MockComponent
    private AdvisoryImporter advisoryImporter;

    @MockComponent
    private SecurityAdvisoriesManager advisoriesManager;

    @MockComponent
    private DisclosedAdvisoryPublisher disclosedAdvisoryPublisher;

    @RegisterExtension
    private LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.INFO);

    private XWikiDocument createImportedAdvisory(DocumentReference reference, List<ExternalUser> externalUsers)
        throws Exception
    {
        XWikiContext context = this.oldcore.getXWikiContext();
        XWikiDocument document = new XWikiDocument(reference);
        BaseObject advisoryObject =
            document.newXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE, context);
        advisoryObject.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE, "DRAFT");
        advisoryObject.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ADVISORY_LINK,
            ADVISORY_LINK);
        for (ExternalUser externalUser : externalUsers) {
            document.newXObject(ExternalUserClassMandatoryDocumentInitializer.CLASS_REFERENCE, context)
                .setStringValue(ExternalUserClassMandatoryDocumentInitializer.EXTERNAL_ID, externalUser.id());
        }
        this.oldcore.getSpyXWiki().saveDocument(document, context);
        return document;
    }

    private XWikiDocument createLegacyAdvisory(String name, List<String> modules, List<String> affectedVersions,
        List<String> patchedVersions, String cve) throws Exception
    {
        XWikiContext context = this.oldcore.getXWikiContext();
        DocumentReference reference =
            new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "SecurityEntries"), name);
        XWikiDocument document = new XWikiDocument(reference);
        BaseObject advisoryObject =
            document.newXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE, context);
        advisoryObject.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE, "DRAFT");
        advisoryObject.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_PRODUCT, "xwiki-platform");
        advisoryObject.setStringListValue(SecurityAdvisoryDataMigrator.LEGACY_FIELD_MAVEN_MODULES, modules);
        advisoryObject.setStringListValue(SecurityAdvisoryDataMigrator.LEGACY_FIELD_AFFECTED_VERSIONS,
            affectedVersions);
        advisoryObject.setStringListValue(SecurityAdvisoryDataMigrator.LEGACY_FIELD_PATCHED_VERSIONS, patchedVersions);
        advisoryObject.setStringValue(SecurityAdvisoryDataMigrator.LEGACY_FIELD_CVE, cve);
        this.oldcore.getSpyXWiki().saveDocument(document, context);
        return document;
    }

    private XWikiDocument reload(DocumentReference reference) throws Exception
    {
        return this.oldcore.getSpyXWiki().getDocument(reference, this.oldcore.getXWikiContext());
    }

    private void assertSingleMigrationLog(DocumentReference reference)
    {
        assertEquals(1, this.logCapture.size());
        assertEquals(String.format("Migrated security advisory [%s] to the new data model.", reference),
            this.logCapture.getMessage(0));
    }

    @Test
    void migrateMovesImpactedPackages() throws Exception
    {
        XWikiDocument document = createLegacyAdvisory("Advisory1",
            List.of("org.xwiki.platform:xwiki-platform-oldcore", "org.xwiki.commons:xwiki-commons-component-api"),
            List.of("<15.10"), List.of("15.10", "16.4.0"), "CVE-2024-0001");

        assertTrue(this.migrator.migrate(document.getDocumentReference()));

        XWikiDocument migrated = reload(document.getDocumentReference());
        List<BaseObject> packages =
            migrated.getXObjects(ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        assertEquals(2, packages.size());

        BaseObject firstPackage = packages.get(0);
        assertEquals("org.xwiki.platform:xwiki-platform-oldcore",
            firstPackage.getStringValue(ImpactedPackageClassMandatoryDocumentInitializer.PACKAGE_ID));
        assertEquals(SecurityAdvisoryDataMigrator.MAVEN_ECOSYSTEM,
            firstPackage.getStringValue(ImpactedPackageClassMandatoryDocumentInitializer.ECOSYSTEM));
        assertEquals(List.of("<15.10"),
            firstPackage.getListValue(ImpactedPackageClassMandatoryDocumentInitializer.VULNERABLE_VERSION_RANGE));
        assertEquals(List.of("15.10", "16.4.0"),
            firstPackage.getListValue(ImpactedPackageClassMandatoryDocumentInitializer.PATCHED_VERSIONS));
        assertEquals("org.xwiki.commons:xwiki-commons-component-api",
            packages.get(1).getStringValue(ImpactedPackageClassMandatoryDocumentInitializer.PACKAGE_ID));

        assertSingleMigrationLog(document.getDocumentReference());

        // The CVE has been migrated and the legacy properties have been dropped.
        BaseObject advisoryObject =
            migrated.getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        assertEquals("CVE-2024-0001",
            advisoryObject.getStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVE_ID));
        assertNull(advisoryObject.safeget(SecurityAdvisoryDataMigrator.LEGACY_FIELD_CVE));
        assertNull(advisoryObject.safeget(SecurityAdvisoryDataMigrator.LEGACY_FIELD_MAVEN_MODULES));
        assertNull(advisoryObject.safeget(SecurityAdvisoryDataMigrator.LEGACY_FIELD_AFFECTED_VERSIONS));
        assertNull(advisoryObject.safeget(SecurityAdvisoryDataMigrator.LEGACY_FIELD_PATCHED_VERSIONS));
    }

    @Test
    void migrateWithoutModulesCreatesSinglePackage() throws Exception
    {
        XWikiDocument document =
            createLegacyAdvisory("Advisory2", List.of(), List.of("<1.0"), List.of("1.0"), "");

        assertTrue(this.migrator.migrate(document.getDocumentReference()));

        XWikiDocument migrated = reload(document.getDocumentReference());
        List<BaseObject> packages =
            migrated.getXObjects(ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        assertEquals(1, packages.size());
        assertEquals("",
            packages.get(0).getStringValue(ImpactedPackageClassMandatoryDocumentInitializer.PACKAGE_ID));
        assertEquals(List.of("<1.0"),
            packages.get(0).getListValue(ImpactedPackageClassMandatoryDocumentInitializer.VULNERABLE_VERSION_RANGE));

        assertSingleMigrationLog(document.getDocumentReference());
    }

    @Test
    void migrateIsIdempotent() throws Exception
    {
        XWikiDocument document = createLegacyAdvisory("Advisory3",
            List.of("org.xwiki.platform:xwiki-platform-oldcore"), List.of("<15.10"), List.of("15.10"), "");

        assertTrue(this.migrator.migrate(document.getDocumentReference()));
        // A second run must not change anything as the document no longer holds legacy data.
        assertFalse(this.migrator.migrate(document.getDocumentReference()));

        XWikiDocument migrated = reload(document.getDocumentReference());
        assertEquals(1,
            migrated.getXObjects(ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE).size());

        // Only the first run produces a migration log.
        assertSingleMigrationLog(document.getDocumentReference());
    }

    @ParameterizedTest
    @MethodSource("advisorySpaces")
    void migrateImportsMissingExternalUsers(List<String> space) throws Exception
    {
        // Once published, the advisory held in the public data space is the one getting the external users, as for an
        // import.
        DocumentReference reference = new DocumentReference("xwiki", space, "GHSA-8469-jx93-r677");
        XWikiDocument document = createImportedAdvisory(reference, List.of());
        SecurityAdvisory importedAdvisory = new SecurityAdvisory(reference).setTitle("Title on GitHub")
            .setExternalUsers(EXTERNAL_USERS);
        when(this.advisoryImporter.importAdvisory(ADVISORY_LINK)).thenReturn(importedAdvisory);
        when(this.advisoriesManager.writeAdvisoryExternalUsers(any())).thenReturn(true);

        assertTrue(this.migrator.migrate(reference));

        // Only the external users of the imported advisory are written.
        verify(this.advisoriesManager).writeAdvisoryExternalUsers(argThat(advisory ->
            reference.equals(advisory.getHolderReference()) && EXTERNAL_USERS.equals(advisory.getExternalUsers())
                && advisory.getTitle() == null));
        verify(this.advisoriesManager, never()).writeAdvisory(any());
        // The legacy data migration has nothing to do on the document.
        assertEquals(document.getVersion(), reload(reference).getVersion());
        assertEquals(1, this.logCapture.size());
        assertEquals(String.format("Imported the external users of security advisory [%s].", reference),
            this.logCapture.getMessage(0));
    }

    static Stream<List<String>> advisorySpaces()
    {
        return Stream.of(ENTRIES_SPACE, PUBLIC_SPACE);
    }

    private void mockPublishedOriginal(DocumentReference reference)
    {
        when(this.disclosedAdvisoryPublisher.isPublishedOriginal(
            argThat(document -> document != null && reference.equals(document.getDocumentReference()))))
            .thenReturn(true);
    }

    @Test
    void migrateSkipsAdvisoriesNotMissingExternalUsers() throws Exception
    {
        DocumentReference withExternalUsers = new DocumentReference("xwiki", ENTRIES_SPACE, "GHSA-with-users");
        createImportedAdvisory(withExternalUsers, EXTERNAL_USERS);
        // The original of a published advisory only redirects to the published one.
        DocumentReference publishedOriginal = new DocumentReference("xwiki", ENTRIES_SPACE, "GHSA-published");
        createImportedAdvisory(publishedOriginal, List.of());
        mockPublishedOriginal(publishedOriginal);

        assertFalse(this.migrator.migrate(withExternalUsers));
        assertFalse(this.migrator.migrate(publishedOriginal));

        verify(this.advisoryImporter, never()).importAdvisory(anyString());
        verify(this.advisoriesManager, never()).writeAdvisoryExternalUsers(any());
    }

    private void mockDocumentsToMigrateQueries() throws Exception
    {
        Query legacyQuery = mock(Query.class);
        when(this.queryManager.createQuery(contains("legacyProp"), eq(Query.HQL))).thenReturn(legacyQuery);
        when(legacyQuery.bindValue(anyString(), any())).thenReturn(legacyQuery);
        when(legacyQuery.execute()).thenReturn(List.of("SecurityAdvisoryApplication.SecurityEntries.Advisory4",
            "SecurityAdvisoryApplication.SecurityEntries.Advisory5"));

        Query externalUsersQuery = mock(Query.class);
        when(this.queryManager.createQuery(contains("externalUserObj"), eq(Query.HQL)))
            .thenReturn(externalUsersQuery);
        when(externalUsersQuery.bindValue(anyString(), any())).thenReturn(externalUsersQuery);
        when(externalUsersQuery.execute()).thenReturn(List.of(
            // Both holding legacy data and missing its external users.
            new Object[] {"SecurityAdvisoryApplication.SecurityEntries.Advisory5", ADVISORY_LINK},
            new Object[] {"SecurityAdvisoryApplication.SecurityEntries.Advisory6", ADVISORY_LINK},
            // Without advisory link, so there's nothing to import the external users from.
            new Object[] {"SecurityAdvisoryApplication.SecurityEntries.Advisory7", " "},
            new Object[] {"SecurityAdvisoryApplication.DisclosedEntries.Advisory8", ADVISORY_LINK},
            new Object[] {"SecurityAdvisoryApplication.SecurityEntries.Advisory9", ADVISORY_LINK}));
        mockPublishedOriginal(new DocumentReference("xwiki", ENTRIES_SPACE, "Advisory9"));
    }

    @Test
    void getDocumentsToMigrate() throws Exception
    {
        mockDocumentsToMigrateQueries();

        assertEquals(List.of(new DocumentReference("xwiki", ENTRIES_SPACE, "Advisory4"),
            new DocumentReference("xwiki", ENTRIES_SPACE, "Advisory5"),
            new DocumentReference("xwiki", ENTRIES_SPACE, "Advisory6"),
            new DocumentReference("xwiki", PUBLIC_SPACE, "Advisory8")), this.migrator.getDocumentsToMigrate());
    }

    @Test
    void countDocumentsToMigrate() throws Exception
    {
        mockDocumentsToMigrateQueries();

        assertEquals(4L, this.migrator.countDocumentsToMigrate());
    }
}
