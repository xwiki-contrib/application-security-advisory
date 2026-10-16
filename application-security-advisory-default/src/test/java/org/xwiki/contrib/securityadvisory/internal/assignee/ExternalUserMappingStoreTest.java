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
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.securityadvisory.ExternalUser;
import org.xwiki.contrib.securityadvisory.internal.configuration.SecurityAdvisoryConfigurationSource;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.user.UserReference;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link ExternalUserMappingStore}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class ExternalUserMappingStoreTest
{
    private static final ExternalUser SURLI = new ExternalUser("1478232", "surli");

    private static final ExternalUser OANAT = new ExternalUser("370535", "oanat");

    @InjectMockComponents
    private ExternalUserMappingStore store;

    @MockComponent
    private UserPropertyConverter userPropertyConverter;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    private UserReference userA;

    private UserReference userB;

    private DocumentReference configurationReference;

    @BeforeEach
    void setUp()
    {
        this.configurationReference =
            new DocumentReference(SecurityAdvisoryConfigurationSource.DOC_REFERENCE, this.oldcore.getXWikiContext()
                .getWikiReference());
        this.userA = mock(UserReference.class);
        this.userB = mock(UserReference.class);
        when(this.userPropertyConverter.serialize(eq(this.userA), any(EntityReference.class))).thenReturn("XWiki.A");
        when(this.userPropertyConverter.serialize(eq(this.userB), any(EntityReference.class))).thenReturn("XWiki.B");
        when(this.userPropertyConverter.resolve(eq("XWiki.A"), any(EntityReference.class)))
            .thenReturn(Optional.of(this.userA));
        when(this.userPropertyConverter.resolve(eq("XWiki.B"), any(EntityReference.class)))
            .thenReturn(Optional.of(this.userB));
    }

    private List<BaseObject> getMappingObjects() throws Exception
    {
        XWikiDocument configurationDocument =
            this.oldcore.getSpyXWiki().getDocument(this.configurationReference, this.oldcore.getXWikiContext());
        return configurationDocument.getXObjects(ExternalUserMappingClassMandatoryDocumentInitializer.CLASS_REFERENCE);
    }

    @Test
    void setMappingCreatesThenReplacesMapping() throws Exception
    {
        assertEquals(Optional.empty(), this.store.getMappedUser(SURLI.id()));

        this.store.setMapping(SURLI, this.userA);
        assertEquals(Optional.of(this.userA), this.store.getMappedUser(SURLI.id()));

        // Mapping the same external user again, after they renamed their account, replaces the existing mapping.
        this.store.setMapping(new ExternalUser(SURLI.id(), "surli-renamed"), this.userB);
        assertEquals(Optional.of(this.userB), this.store.getMappedUser(SURLI.id()));

        List<BaseObject> mappingObjects = getMappingObjects();
        assertEquals(1, mappingObjects.size());
        BaseObject mappingObject = mappingObjects.get(0);
        assertEquals(SURLI.id(),
            mappingObject.getStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.EXTERNAL_ID));
        assertEquals("surli-renamed",
            mappingObject.getStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.LOGIN));
        assertEquals("XWiki.B",
            mappingObject.getLargeStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.USER));
    }

    @Test
    void resolveAssigneeUsesFirstMappedExternalUser() throws Exception
    {
        assertTrue(this.store.resolveAssignee(List.of(SURLI, OANAT)).isEmpty());

        this.store.setMapping(OANAT, this.userB);
        assertEquals(Optional.of(this.userB), this.store.resolveAssignee(List.of(SURLI, OANAT)));

        this.store.setMapping(SURLI, this.userA);
        assertEquals(Optional.of(this.userA), this.store.resolveAssignee(List.of(SURLI, OANAT)));
        assertEquals(Optional.of(this.userB), this.store.resolveAssignee(List.of(OANAT, SURLI)));
    }
}
