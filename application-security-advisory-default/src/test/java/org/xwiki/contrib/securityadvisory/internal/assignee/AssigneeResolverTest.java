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
import org.xwiki.contrib.securityadvisory.SecurityAdvisoriesManager;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryApplicationClassMandatoryDocumentInitializer;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryManager;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link AssigneeResolver}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class AssigneeResolverTest
{
    private static final ExternalUser SURLI = new ExternalUser("github", "1478232", "surli");

    private static final ExternalUser OANAT = new ExternalUser("github", "370535", "oanat");

    private static final ExternalUser REPORTER = new ExternalUser("github", "42", "reporter");

    @InjectMockComponents
    private AssigneeResolver resolver;

    @MockComponent
    private SecurityAdvisoriesManager securityAdvisoriesManager;

    @MockComponent
    private ExternalUserMappingStore externalUserMappingStore;

    @MockComponent
    private UserPropertyConverter userPropertyConverter;

    @MockComponent
    private QueryManager queryManager;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    private UserReference mappedUser;

    @BeforeEach
    void setUp() throws Exception
    {
        this.mappedUser = mock(UserReference.class);
        when(this.externalUserMappingStore.getMappedUser(any())).thenReturn(Optional.empty());
        when(this.externalUserMappingStore.getMappedUser(OANAT)).thenReturn(Optional.of(this.mappedUser));
        when(this.externalUserMappingStore.resolveAssignee(anyList())).thenReturn(Optional.empty());
        when(this.externalUserMappingStore.resolveAssignee(List.of(REPORTER, OANAT)))
            .thenReturn(Optional.of(this.mappedUser));
        when(this.externalUserMappingStore.resolveAssignee(List.of(OANAT))).thenReturn(Optional.of(this.mappedUser));
    }

    private DocumentReference advisoryReference(String name)
    {
        return new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "SecurityEntries"), name);
    }

    private SecurityAdvisory registerAdvisory(String name, UserReference assignee, ExternalUser... externalUsers)
        throws Exception
    {
        DocumentReference reference = advisoryReference(name);
        SecurityAdvisory advisory = new SecurityAdvisory(reference)
            .setAssignee(assignee)
            .setExternalUsers(List.of(externalUsers));
        when(this.securityAdvisoriesManager.loadAdvisory(reference)).thenReturn(Optional.of(advisory));
        return advisory;
    }

    private XWikiDocument saveAdvisoryDocument(String name, String assignee) throws Exception
    {
        XWikiContext context = this.oldcore.getXWikiContext();
        XWikiDocument document = new XWikiDocument(advisoryReference(name));
        BaseObject advisoryObject =
            document.newXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE, context);
        if (assignee != null) {
            advisoryObject.setLargeStringValue(
                SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE, assignee);
        }
        this.oldcore.getSpyXWiki().saveDocument(document, context);
        return document;
    }

    private String getAssignee(String name) throws Exception
    {
        return this.oldcore.getSpyXWiki().getDocument(advisoryReference(name), this.oldcore.getXWikiContext())
            .getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE)
            .getLargeStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE);
    }

    @Test
    void getUnmappedExternalUsersOfAdvisory() throws Exception
    {
        SecurityAdvisory unassigned = registerAdvisory("Unassigned", null, REPORTER, OANAT, SURLI);
        assertEquals(List.of(REPORTER, SURLI), this.resolver.getUnmappedExternalUsers(unassigned));

        // An archived external user is not proposed for mapping anymore.
        when(this.externalUserMappingStore.isArchived(REPORTER)).thenReturn(true);
        assertEquals(List.of(SURLI), this.resolver.getUnmappedExternalUsers(unassigned));

        SecurityAdvisory assigned = registerAdvisory("Assigned", mock(UserReference.class), SURLI);
        assertEquals(List.of(), this.resolver.getUnmappedExternalUsers(assigned));
    }

    @Test
    void countUnassignedAdvisories() throws Exception
    {
        registerAdvisory("Advisory1", null, SURLI, REPORTER);
        registerAdvisory("Advisory2", null, OANAT, SURLI);
        registerAdvisory("Advisory3", mock(UserReference.class), SURLI);

        Query query = mock(Query.class);
        when(this.queryManager.createQuery(anyString(), eq(Query.XWQL))).thenReturn(query);
        when(query.bindValue(anyString(), any())).thenReturn(query);
        // A document holding several external user objects can be returned several times.
        when(query.execute()).thenReturn(List.of(
            "SecurityAdvisoryApplication.SecurityEntries.Advisory1",
            "SecurityAdvisoryApplication.SecurityEntries.Advisory2",
            "SecurityAdvisoryApplication.SecurityEntries.Advisory2",
            "SecurityAdvisoryApplication.SecurityEntries.Advisory3"));

        // The assigned advisory is not counted, and each advisory is counted once.
        assertEquals(2, this.resolver.countUnassignedAdvisories(SURLI));
        verify(query).bindValue("hint", "github");
        verify(query).bindValue("externalId", SURLI.id());
    }

    @Test
    void resolveAssignee() throws Exception
    {
        UserReference author = mock(UserReference.class);
        DocumentReference reference = saveAdvisoryDocument("Advisory", null).getDocumentReference();
        registerAdvisory("Advisory", null, REPORTER, OANAT);
        when(this.userPropertyConverter.serialize(this.mappedUser, reference)).thenReturn("XWiki.oanat");

        assertTrue(this.resolver.resolveAssignee(reference, author));

        assertEquals("XWiki.oanat", getAssignee("Advisory"));
        XWikiDocument document =
            this.oldcore.getSpyXWiki().getDocument(reference, this.oldcore.getXWikiContext());
        assertEquals(author, document.getAuthors().getEffectiveMetadataAuthor());
    }

    @Test
    void resolveAssigneeWithoutMapping() throws Exception
    {
        DocumentReference reference = saveAdvisoryDocument("Advisory", null).getDocumentReference();
        registerAdvisory("Advisory", null, REPORTER, SURLI);

        assertFalse(this.resolver.resolveAssignee(reference, mock(UserReference.class)));
        assertEquals("", getAssignee("Advisory"));
    }

    @Test
    void resolveAssigneeDoesNotOverrideAssignee() throws Exception
    {
        // The advisory was assigned by hand since it was loaded.
        DocumentReference reference = saveAdvisoryDocument("Advisory", "XWiki.someone").getDocumentReference();
        registerAdvisory("Advisory", null, OANAT);

        assertFalse(this.resolver.resolveAssignee(reference, mock(UserReference.class)));
        assertEquals("XWiki.someone", getAssignee("Advisory"));

        registerAdvisory("Advisory", mock(UserReference.class), OANAT);
        assertFalse(this.resolver.resolveAssignee(reference, mock(UserReference.class)));
    }
}
