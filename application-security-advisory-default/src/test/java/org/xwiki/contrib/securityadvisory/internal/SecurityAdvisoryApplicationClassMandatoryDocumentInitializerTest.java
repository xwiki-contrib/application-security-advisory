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

import javax.inject.Named;

import org.junit.jupiter.api.Test;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.properties.internal.DefaultConverterManager;
import org.xwiki.properties.internal.converter.ConvertUtilsConverter;
import org.xwiki.properties.internal.converter.EnumConverter;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link SecurityAdvisoryApplicationClassMandatoryDocumentInitializer}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
@ComponentList({
    DefaultConverterManager.class,
    ConvertUtilsConverter.class,
    EnumConverter.class
})
class SecurityAdvisoryApplicationClassMandatoryDocumentInitializerTest
{
    @InjectMockComponents
    private SecurityAdvisoryApplicationClassMandatoryDocumentInitializer initializer;

    @MockComponent
    private SheetBinder documentSheetBinder;

    @MockComponent
    @Named("class")
    private SheetBinder classSheetBinder;

    @MockComponent
    private WikiDescriptorManager wikiDescriptorManager;

    @Test
    void updateDocumentRemovesObsoleteFields()
    {
        XWikiDocument document =
            new XWikiDocument(new DocumentReference("xwiki",
                SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CODE_SPACE_LIST,
                "SecurityAdvisoryApplicationClass"));

        // Simulate a class coming from the legacy data model: it still holds the fields that have been replaced by the
        // impacted package objects and the cveId field.
        BaseClass xclass = document.getXClass();
        xclass.addStaticListField("mavenModules", "mavenModules", 1, true, "");
        xclass.addStaticListField("affectedVersions", "affectedVersions", 1, true, "");
        xclass.addStaticListField("patchedVersions", "patchedVersions", 1, true, "");
        xclass.addTextField("cve", "cve", 255);
        xclass.addTextField("dataSpaceName", "dataSpaceName", 255);
        xclass.addStaticListField("jiraTickets", "jiraTickets", 1, true, "");

        assertTrue(this.initializer.updateDocument(document));

        // The obsolete fields have been removed from the class.
        assertNull(xclass.getField("mavenModules"));
        assertNull(xclass.getField("affectedVersions"));
        assertNull(xclass.getField("patchedVersions"));
        assertNull(xclass.getField("cve"));
        assertNull(xclass.getField("dataSpaceName"));
        assertNull(xclass.getField("jiraTickets"));

        // The fields of the new data model are present.
        assertNotNull(xclass.getField(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVE_ID));
        assertNotNull(xclass.getField(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE));
        assertNotNull(xclass.getField(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_PRODUCT));
    }
}
