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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.bridge.event.DocumentCreatingEvent;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryApplicationClassMandatoryDocumentInitializer;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.user.UserReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link CreatorAssigneeListener}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class CreatorAssigneeListenerTest
{
    @InjectMockComponents
    private CreatorAssigneeListener listener;

    @MockComponent
    private SecurityAdvisoryConfiguration configuration;

    @MockComponent
    private UserPropertyConverter userPropertyConverter;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    private UserReference creator;

    private XWikiDocument document;

    private BaseObject advisoryObject;

    @BeforeEach
    void setUp() throws Exception
    {
        XWikiContext context = this.oldcore.getXWikiContext();
        this.document = new XWikiDocument(
            new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "SecurityEntries"), "Advisory"));
        this.advisoryObject = this.document.newXObject(
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE, context);
        this.creator = mock(UserReference.class);
        this.document.getAuthors().setCreator(this.creator);
        when(this.userPropertyConverter.serialize(this.creator, this.document.getDocumentReference()))
            .thenReturn("XWiki.creator");
        when(this.configuration.getAdvisoryImporterUser()).thenReturn(mock(UserReference.class));
    }

    private String getAssignee()
    {
        return this.advisoryObject.getLargeStringValue(
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE);
    }

    @Test
    void assignCreatorOfAdvisoryCreatedByHand()
    {
        this.listener.onEvent(new DocumentCreatingEvent(), this.document, null);

        assertEquals("XWiki.creator", getAssignee());
    }

    @Test
    void keepAssigneeSetAtCreation()
    {
        this.advisoryObject.setLargeStringValue(
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE, "XWiki.other");

        this.listener.onEvent(new DocumentCreatingEvent(), this.document, null);

        assertEquals("XWiki.other", getAssignee());
    }

    @Test
    void doNotAssignImportedAdvisory() throws Exception
    {
        // An advisory imported with external users is assigned from their mapping.
        this.document.newXObject(ExternalUserClassMandatoryDocumentInitializer.CLASS_REFERENCE,
            this.oldcore.getXWikiContext());

        this.listener.onEvent(new DocumentCreatingEvent(), this.document, null);

        assertEquals("", getAssignee());
    }

    @Test
    void doNotAssignPublicationOfDisclosedAdvisory()
    {
        when(this.configuration.getPublicDataSpace())
            .thenReturn(this.document.getDocumentReference().getLastSpaceReference());

        this.listener.onEvent(new DocumentCreatingEvent(), this.document, null);

        assertEquals("", getAssignee());
    }

    @Test
    void doNotAssignImporterUser()
    {
        when(this.configuration.getAdvisoryImporterUser()).thenReturn(this.creator);

        this.listener.onEvent(new DocumentCreatingEvent(), this.document, null);

        assertEquals("", getAssignee());
    }

    @Test
    void ignoreOtherDocuments()
    {
        XWikiDocument otherDocument = new XWikiDocument(new DocumentReference("xwiki", "Space", "Page"));
        otherDocument.getAuthors().setCreator(this.creator);

        this.listener.onEvent(new DocumentCreatingEvent(), otherDocument, null);

        assertEquals(List.of(), otherDocument.getXObjects(
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE));
    }
}
