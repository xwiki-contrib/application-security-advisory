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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
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
    @InjectMockComponents
    private SecurityAdvisoryDataMigrator migrator;

    @MockComponent
    private QueryManager queryManager;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @RegisterExtension
    private LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.INFO);

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

    @Test
    void getDocumentsToMigrate() throws Exception
    {
        Query query = mock(Query.class);
        when(this.queryManager.createQuery(anyString(), eq(Query.HQL))).thenReturn(query);
        when(query.bindValue(anyString(), any())).thenReturn(query);
        when(query.execute()).thenReturn(List.of("SecurityAdvisoryApplication.SecurityEntries.Advisory4"));

        List<DocumentReference> documentsToMigrate = this.migrator.getDocumentsToMigrate();

        assertEquals(1, documentsToMigrate.size());
        assertEquals(
            new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "SecurityEntries"), "Advisory4"),
            documentsToMigrate.get(0));
        // The query is constrained to the advisory class and the legacy fields.
        verify(query).bindValue("className", "SecurityAdvisoryApplication.Code.SecurityAdvisoryApplicationClass");
        verify(query).bindValue("legacyFields",
            List.of("mavenModules", "affectedVersions", "patchedVersions", "cve"));
    }

    @Test
    void countDocumentsToMigrate() throws Exception
    {
        Query query = mock(Query.class);
        when(this.queryManager.createQuery(anyString(), eq(Query.HQL))).thenReturn(query);
        when(query.bindValue(anyString(), any())).thenReturn(query);
        when(query.execute()).thenReturn(List.of(3L));

        assertEquals(3L, this.migrator.countDocumentsToMigrate());
    }
}
