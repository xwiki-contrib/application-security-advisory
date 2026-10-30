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

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.securityadvisory.ExternalUser;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.event.AdvisoryStateChangedEvent;
import org.xwiki.contrib.securityadvisory.internal.assignee.ExternalUserMappingStore;
import org.xwiki.contrib.securityadvisory.internal.assignee.UserPropertyConverter;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.observation.ObservationManager;
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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DefaultSecurityAdvisoriesManager}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class DefaultSecurityAdvisoriesManagerTest
{
    private static final DocumentReference ADVISORY_REFERENCE =
        new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "SecurityEntries"), "GHSA-test");

    private static final DocumentReference PUBLIC_REFERENCE =
        new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "DisclosedEntries"), "GHSA-test");

    private static final List<ExternalUser> EXTERNAL_USERS =
        List.of(new ExternalUser("github", "42", "reporter"), new ExternalUser("github", "1478232", "surli"));

    private static final String ADVISORY_LINK = "https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-test";

    @InjectMockComponents
    private DefaultSecurityAdvisoriesManager manager;

    @MockComponent
    private DisclosedAdvisoryPublisher publisher;

    @MockComponent
    private QueryManager queryManager;

    @MockComponent
    private ExternalUserMappingStore externalUserMappingStore;

    @MockComponent
    private UserPropertyConverter userPropertyConverter;

    @MockComponent
    private ObservationManager observationManager;

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
            .setAdvisoryLink(ADVISORY_LINK)
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

        // The external users are registered, so that administrators can map them.
        for (ExternalUser externalUser : EXTERNAL_USERS) {
            verify(this.externalUserMappingStore).register(externalUser);
        }

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

    private XWikiDocument createAdvisory(DocumentReference reference, String state) throws Exception
    {
        XWikiContext context = this.oldcore.getXWikiContext();
        XWikiDocument document = new XWikiDocument(reference);
        BaseObject advisoryObject =
            document.newXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE, context);
        advisoryObject.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE, state);
        advisoryObject.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ADVISORY_LINK,
            ADVISORY_LINK);
        this.oldcore.getSpyXWiki().saveDocument(document, context);
        return document;
    }

    private String getState(DocumentReference reference) throws Exception
    {
        return this.oldcore.getSpyXWiki().getDocument(reference, this.oldcore.getXWikiContext())
            .getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE)
            .getStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE);
    }

    @Test
    void setStatusDisclosedPublishesTheAdvisory() throws Exception
    {
        createAdvisory(ADVISORY_REFERENCE, "DISCLOSABLE");
        createAdvisory(PUBLIC_REFERENCE, "DISCLOSED");
        when(this.publisher.publish(ADVISORY_REFERENCE)).thenReturn(PUBLIC_REFERENCE);
        SecurityAdvisory advisory = this.manager.loadAdvisory(ADVISORY_REFERENCE).get();

        this.manager.setStatus(advisory, SecurityAdvisory.State.DISCLOSED);

        verify(this.publisher).publish(ADVISORY_REFERENCE);
        // The publisher is the one saving the new state.
        assertEquals("DISCLOSABLE", getState(ADVISORY_REFERENCE));
        verify(this.observationManager).notify(any(AdvisoryStateChangedEvent.class),
            argThat((SecurityAdvisory source) -> PUBLIC_REFERENCE.equals(source.getHolderReference())),
            eq(Pair.of(SecurityAdvisory.State.DISCLOSABLE, SecurityAdvisory.State.DISCLOSED)));
    }

    @Test
    void setStatusOtherThanDisclosedDoesNotPublish() throws Exception
    {
        createAdvisory(ADVISORY_REFERENCE, "DISCLOSABLE");
        SecurityAdvisory advisory = this.manager.loadAdvisory(ADVISORY_REFERENCE).get();

        this.manager.setStatus(advisory, SecurityAdvisory.State.ANNOUNCED);

        verify(this.publisher, never()).publish(any());
        assertEquals("ANNOUNCED", getState(ADVISORY_REFERENCE));
    }

    @Test
    void findExistingAdvisoryIgnoresPublishedOriginals() throws Exception
    {
        createAdvisory(ADVISORY_REFERENCE, "DISCLOSED");
        createAdvisory(PUBLIC_REFERENCE, "DISCLOSED");
        when(this.publisher.isPublishedOriginal(argThat(
            (XWikiDocument document) -> ADVISORY_REFERENCE.equals(document.getDocumentReference())))).thenReturn(true);

        Query query = mock(Query.class);
        when(this.queryManager.createQuery(anyString(), any())).thenReturn(query);
        when(query.bindValue("advisoryUrl", ADVISORY_LINK)).thenReturn(query);
        when(query.execute()).thenReturn(List.of(
            "xwiki:SecurityAdvisoryApplication.SecurityEntries.GHSA-test",
            "xwiki:SecurityAdvisoryApplication.DisclosedEntries.GHSA-test"));

        Optional<SecurityAdvisory> result = this.manager.findExistingAdvisory(ADVISORY_LINK);

        assertTrue(result.isPresent());
        assertEquals(PUBLIC_REFERENCE, result.get().getHolderReference());
    }
}
