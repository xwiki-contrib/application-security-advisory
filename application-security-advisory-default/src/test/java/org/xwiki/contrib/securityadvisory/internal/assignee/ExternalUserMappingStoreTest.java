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
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceSerializer;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import jakarta.inject.Named;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
    private static final ExternalUser SURLI = new ExternalUser("github", "1478232", "surli");

    private static final ExternalUser OANAT = new ExternalUser("github", "370535", "oanat");

    private static final DocumentReference ADMIN = new DocumentReference("xwiki", "XWiki", "Admin");

    private static final DocumentReference EDITOR = new DocumentReference("xwiki", "XWiki", "Editor");

    @InjectMockComponents
    private ExternalUserMappingStore store;

    @MockComponent
    private UserPropertyConverter userPropertyConverter;

    @MockComponent
    private AuthorizationManager authorizationManager;

    @MockComponent
    @Named("document")
    private UserReferenceSerializer<DocumentReference> userReferenceSerializer;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    private UserReference userA;

    private UserReference userB;

    @BeforeEach
    void setUp()
    {
        this.userA = mock(UserReference.class);
        this.userB = mock(UserReference.class);
        when(this.userPropertyConverter.serialize(eq(this.userA), any(EntityReference.class))).thenReturn("XWiki.A");
        when(this.userPropertyConverter.serialize(eq(this.userB), any(EntityReference.class))).thenReturn("XWiki.B");
        when(this.userPropertyConverter.resolve(eq("XWiki.A"), any(EntityReference.class)))
            .thenReturn(Optional.of(this.userA));
        when(this.userPropertyConverter.resolve(eq("XWiki.B"), any(EntityReference.class)))
            .thenReturn(Optional.of(this.userB));

        // The pages are saved by the context user, an administrator.
        this.oldcore.getXWikiContext().setUserReference(ADMIN);
        when(this.userReferenceSerializer.serialize(any())).thenReturn(ADMIN);
        when(this.authorizationManager.hasAccess(eq(Right.ADMIN), eq(ADMIN), any())).thenReturn(true);
    }

    private XWikiDocument getDocument(ExternalUser externalUser) throws Exception
    {
        return this.oldcore.getSpyXWiki().getDocument(this.store.getReference(externalUser),
            this.oldcore.getXWikiContext());
    }

    private BaseObject getObject(ExternalUser externalUser) throws Exception
    {
        return getDocument(externalUser).getXObject(ExternalUserMappingClassMandatoryDocumentInitializer.CLASS_REFERENCE);
    }

    @Test
    void getReference()
    {
        assertEquals(new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "ExternalUsers"),
            "github-1478232"), this.store.getReference(SURLI));
    }

    @Test
    void setMappingCreatesThenReplacesMapping() throws Exception
    {
        assertEquals(Optional.empty(), this.store.getMappedUser(SURLI));

        this.store.setMapping(SURLI, this.userA);
        assertEquals(Optional.of(this.userA), this.store.getMappedUser(SURLI));
        assertTrue(getDocument(SURLI).isHidden());

        // Mapping the same external user again, after they renamed their account, replaces the existing mapping.
        this.store.setMapping(new ExternalUser("github", SURLI.id(), "surli-renamed"), this.userB);
        assertEquals(Optional.of(this.userB), this.store.getMappedUser(SURLI));

        BaseObject mappingObject = getObject(SURLI);
        assertEquals("github", mappingObject.getStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.HINT));
        assertEquals(SURLI.id(),
            mappingObject.getStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.EXTERNAL_ID));
        assertEquals("surli-renamed",
            mappingObject.getStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.LOGIN));
        assertEquals("XWiki.B",
            mappingObject.getLargeStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.USER));
    }

    @Test
    void mappingNotSavedByAdministratorIsIgnored() throws Exception
    {
        this.store.setMapping(SURLI, this.userA);

        // The page was last saved by a user who is not an administrator, e.g. by editing it directly.
        when(this.userReferenceSerializer.serialize(any())).thenReturn(EDITOR);

        assertEquals(Optional.empty(), this.store.getMappedUser(SURLI));
    }

    @Test
    void mappingIsSpecificToExternalSystem() throws Exception
    {
        this.store.setMapping(SURLI, this.userA);

        // The same identifier in another external system is another user.
        ExternalUser otherSystemUser = new ExternalUser("other", SURLI.id(), SURLI.login());
        assertEquals(Optional.empty(), this.store.getMappedUser(otherSystemUser));

        this.store.setMapping(otherSystemUser, this.userB);
        assertEquals(Optional.of(this.userA), this.store.getMappedUser(SURLI));
        assertEquals(Optional.of(this.userB), this.store.getMappedUser(otherSystemUser));
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

    @Test
    void setArchived() throws Exception
    {
        assertFalse(this.store.isArchived(SURLI));

        this.store.setArchived(SURLI, true);
        assertTrue(this.store.isArchived(SURLI));
        assertEquals(Optional.empty(), this.store.getMappedUser(SURLI));

        this.store.setArchived(SURLI, false);
        assertFalse(this.store.isArchived(SURLI));

        // Mapping an archived user unarchives it.
        this.store.setArchived(SURLI, true);
        this.store.setMapping(SURLI, this.userA);
        assertFalse(this.store.isArchived(SURLI));
    }

    @Test
    void register() throws Exception
    {
        this.store.register(SURLI);
        BaseObject mappingObject = getObject(SURLI);
        assertEquals("surli", mappingObject.getStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.LOGIN));
        assertEquals("", mappingObject.getLargeStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.USER));
        assertTrue(getDocument(SURLI).isHidden());

        // The login of a user who is not mapped yet is updated when they rename their account.
        this.store.register(new ExternalUser("github", SURLI.id(), "surli-renamed"));
        assertEquals("surli-renamed",
            getObject(SURLI).getStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.LOGIN));

        // The page of a mapped user is left untouched, to keep the mapping authored by the administrator.
        this.store.setMapping(SURLI, this.userA);
        String version = getDocument(SURLI).getVersion();
        this.store.register(new ExternalUser("github", SURLI.id(), "surli-renamed-again"));
        assertEquals(version, getDocument(SURLI).getVersion());
        assertEquals(Optional.of(this.userA), this.store.getMappedUser(SURLI));
    }
}
