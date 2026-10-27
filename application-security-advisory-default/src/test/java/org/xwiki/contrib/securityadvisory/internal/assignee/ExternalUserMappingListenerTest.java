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
import org.xwiki.bridge.event.DocumentUpdatedEvent;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.user.UserReferenceSerializer;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import jakarta.inject.Named;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link ExternalUserMappingListener}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class ExternalUserMappingListenerTest
{
    private static final DocumentReference ADMIN = new DocumentReference("xwiki", "XWiki", "Admin");

    @InjectMockComponents
    private ExternalUserMappingListener listener;

    @MockComponent
    private AssigneeResolutionJobManager jobManager;

    @MockComponent
    @Named("document")
    private UserReferenceSerializer<DocumentReference> userReferenceSerializer;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @BeforeEach
    void setUp()
    {
        when(this.userReferenceSerializer.serialize(any())).thenReturn(ADMIN);
    }

    private XWikiDocument mappingDocument(String user) throws Exception
    {
        XWikiDocument document = new XWikiDocument(
            new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "ExternalUsers"), "github-42"));
        if (user != null) {
            document.newXObject(ExternalUserMappingClassMandatoryDocumentInitializer.CLASS_REFERENCE,
                this.oldcore.getXWikiContext())
                .setLargeStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.USER, user);
        }
        return document;
    }

    private void save(XWikiDocument previous, XWikiDocument current)
    {
        current.setOriginalDocument(previous);
        this.listener.onEvent(new DocumentUpdatedEvent(), current, null);
    }

    @Test
    void startResolutionWhenUserIsMapped() throws Exception
    {
        save(mappingDocument(""), mappingDocument("XWiki.alice"));

        verify(this.jobManager).startResolution(ADMIN);
    }

    @Test
    void startResolutionWhenMappingChanges() throws Exception
    {
        save(mappingDocument("XWiki.alice"), mappingDocument("XWiki.bob"));

        verify(this.jobManager).startResolution(ADMIN);
    }

    @Test
    void ignoreSaveNotChangingTheMapping() throws Exception
    {
        // e.g. archiving or registering the external user.
        save(mappingDocument("XWiki.alice"), mappingDocument("XWiki.alice"));
        save(mappingDocument(""), mappingDocument(""));
        save(mappingDocument("XWiki.alice"), mappingDocument(""));
        save(mappingDocument(null), mappingDocument(null));

        verify(this.jobManager, never()).startResolution(any());
    }
}
