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
package org.xwiki.contrib.securityadvisory.internal.assignee;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.test.junit5.mockito.InjectMockComponents;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link ExternalUsersRightsInitializer}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class ExternalUsersRightsInitializerTest
{
    private static final LocalDocumentReference RIGHTS_CLASS =
        new LocalDocumentReference("XWiki", "XWikiGlobalRights");

    @InjectMockComponents
    private ExternalUsersRightsInitializer initializer;

    @Test
    void restrictSpaceToAdministrators()
    {
        XWikiDocument document = new XWikiDocument(new DocumentReference("xwiki",
            List.of("SecurityAdvisoryApplication", "ExternalUsers"), "WebPreferences"));

        assertTrue(this.initializer.updateDocument(document));

        List<BaseObject> rights = document.getXObjects(RIGHTS_CLASS);
        assertEquals(1, rights.size());
        assertEquals("XWiki.XWikiAdminGroup", rights.get(0).getLargeStringValue("groups"));
        assertEquals("view,edit", rights.get(0).getStringValue("levels"));
        assertEquals(1, rights.get(0).getIntValue("allow"));

        // Existing rights are kept, so that they can be customized.
        assertFalse(this.initializer.updateDocument(document));
        assertEquals(1, document.getXObjects(RIGHTS_CLASS).size());
    }
}
