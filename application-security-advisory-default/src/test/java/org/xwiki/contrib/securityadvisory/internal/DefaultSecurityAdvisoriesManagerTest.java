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
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.securityadvisory.ExternalUser;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.internal.assignee.ExternalUserMappingStore;
import org.xwiki.contrib.securityadvisory.internal.assignee.UserPropertyConverter;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for the assignee handling of {@link DefaultSecurityAdvisoriesManager}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class DefaultSecurityAdvisoriesManagerTest
{
    private static final DocumentReference ADVISORY_REFERENCE =
        new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "SecurityEntries"), "GHSA-test");

    private static final List<ExternalUser> EXTERNAL_USERS =
        List.of(new ExternalUser("42", "reporter"), new ExternalUser("1478232", "surli"));

    @InjectMockComponents
    private DefaultSecurityAdvisoriesManager manager;

    @MockComponent
    private ExternalUserMappingStore externalUserMappingStore;

    @MockComponent
    private UserPropertyConverter userPropertyConverter;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    private UserReference mappedUser;

    @BeforeEach
    void setUp() throws Exception
    {
        this.mappedUser = mock(UserReference.class);
        when(this.externalUserMappingStore.resolveAssignee(EXTERNAL_USERS)).thenReturn(Optional.of(this.mappedUser));
        when(this.userPropertyConverter.serialize(eq(this.mappedUser), any(EntityReference.class)))
            .thenReturn("XWiki.surli");
        when(this.userPropertyConverter.resolve(eq("XWiki.surli"), any(EntityReference.class)))
            .thenReturn(Optional.of(this.mappedUser));
        when(this.userPropertyConverter.resolve(eq(""), any(EntityReference.class))).thenReturn(Optional.empty());
    }

    private SecurityAdvisory importedAdvisory()
    {
        return new SecurityAdvisory(ADVISORY_REFERENCE)
            .setState(SecurityAdvisory.State.DRAFT)
            .setTitle("Title")
            .setContent("Content")
            .setAdvisoryLink("https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-test")
            .setProduct("xwiki-platform")
            .setSeverity("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
            .setCveId("CVE-2026-0001")
            .setExternalUsers(EXTERNAL_USERS);
    }

    private BaseObject getAdvisoryObject() throws Exception
    {
        XWikiDocument document =
            this.oldcore.getSpyXWiki().getDocument(ADVISORY_REFERENCE, this.oldcore.getXWikiContext());
        return document.getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE);
    }

    @Test
    void writeAndLoadAssigneeFromExternalUsers() throws Exception
    {
        this.manager.writeAdvisory(importedAdvisory());

        assertEquals("XWiki.surli", getAdvisoryObject().getLargeStringValue(
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE));

        SecurityAdvisory loadedAdvisory = this.manager.loadAdvisory(ADVISORY_REFERENCE).orElseThrow();
        assertEquals(this.mappedUser, loadedAdvisory.getAssignee());
        assertEquals(EXTERNAL_USERS, loadedAdvisory.getExternalUsers());
    }

    @Test
    void writeAdvisoryKeepsExistingAssignee() throws Exception
    {
        this.manager.writeAdvisory(importedAdvisory().setExternalUsers(List.of()));
        BaseObject advisoryObject = getAdvisoryObject();
        assertEquals("", advisoryObject.getLargeStringValue(
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE));

        // The advisory is assigned by hand, then imported again: the import must not revert the assignee.
        XWikiDocument document = advisoryObject.getOwnerDocument();
        advisoryObject.setLargeStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE,
            "XWiki.someone");
        this.oldcore.getSpyXWiki().saveDocument(document, this.oldcore.getXWikiContext());

        this.manager.writeAdvisory(importedAdvisory());

        assertEquals("XWiki.someone", getAdvisoryObject().getLargeStringValue(
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE));
        verify(this.externalUserMappingStore, never()).resolveAssignee(EXTERNAL_USERS);
    }
}
