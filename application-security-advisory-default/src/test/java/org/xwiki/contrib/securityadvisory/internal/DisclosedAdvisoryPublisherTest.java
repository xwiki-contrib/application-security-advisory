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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryManager;
import org.xwiki.rendering.syntax.Syntax;
import org.xwiki.security.authorization.Right;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceResolver;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import jakarta.inject.Named;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DisclosedAdvisoryPublisher}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class DisclosedAdvisoryPublisherTest
{
    private static final SpaceReference SECURITY_SPACE =
        new SpaceReference("xwiki", "SecurityAdvisoryApplication", "SecurityEntries");

    private static final SpaceReference PUBLIC_SPACE =
        new SpaceReference("xwiki", "SecurityAdvisoryApplication", "DisclosedEntries");

    private static final DocumentReference ADVISORY_REFERENCE = new DocumentReference("GHSA-test", SECURITY_SPACE);

    private static final DocumentReference PUBLIC_REFERENCE = new DocumentReference("GHSA-test", PUBLIC_SPACE);

    private static final DocumentReference DISCLOSER = new DocumentReference("xwiki", "XWiki", "Discloser");

    private static final String ADVISORY_LINK = "https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-test";

    private static final LocalDocumentReference COMMENTS_CLASS = new LocalDocumentReference("XWiki", "XWikiComments");

    @InjectMockComponents
    private DisclosedAdvisoryPublisher publisher;

    @MockComponent
    private SecurityAdvisoryConfiguration configuration;

    @MockComponent
    private QueryManager queryManager;

    @MockComponent
    @Named("document")
    private UserReferenceResolver<DocumentReference> userReferenceResolver;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    private final UserReference reporter = mock(UserReference.class, "reporter");

    private final UserReference discloserUser = mock(UserReference.class, "discloser");

    @BeforeEach
    void setUp()
    {
        when(this.configuration.getPublicDataSpace()).thenReturn(PUBLIC_SPACE);
        when(this.userReferenceResolver.resolve(DISCLOSER)).thenReturn(this.discloserUser);
        this.oldcore.getXWikiContext().setUserReference(DISCLOSER);
        grantEdit(ADVISORY_REFERENCE, true);
        grantEdit(PUBLIC_REFERENCE, true);
    }

    private void grantEdit(DocumentReference reference, boolean granted)
    {
        when(this.oldcore.getMockAuthorizationManager().hasAccess(Right.EDIT, DISCLOSER, reference))
            .thenReturn(granted);
    }

    private XWikiDocument createAdvisory(DocumentReference reference, String state) throws Exception
    {
        XWikiContext context = this.oldcore.getXWikiContext();
        XWikiDocument document = new XWikiDocument(reference);
        document.setTitle("Advisory title");
        document.setSyntax(Syntax.XWIKI_2_1);
        document.setContent("Advisory content");
        document.setEnforceRequiredRights(true);
        document.getAuthors().setContentAuthor(this.reporter);
        document.getAuthors().setEffectiveMetadataAuthor(this.reporter);

        BaseObject advisoryObject =
            document.newXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE, context);
        advisoryObject.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE, state);
        advisoryObject.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ADVISORY_LINK,
            ADVISORY_LINK);
        advisoryObject.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVE_ID,
            "CVE-2026-0001");
        BaseObject packageObject =
            document.newXObject(ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE, context);
        packageObject.setStringValue(ImpactedPackageClassMandatoryDocumentInitializer.PACKAGE_ID, "group:artifact");
        document.newXObject(COMMENTS_CLASS, context).setLargeStringValue("comment", "Private discussion");
        document.setAttachment(new XWikiAttachment(document, "poc.txt"));

        this.oldcore.getSpyXWiki().saveDocument(document, context);
        return document;
    }

    private XWikiDocument load(DocumentReference reference) throws Exception
    {
        return this.oldcore.getSpyXWiki().getDocument(reference, this.oldcore.getXWikiContext());
    }

    private String getState(XWikiDocument document)
    {
        return document.getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE)
            .getStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE);
    }

    @Test
    void publishCopiesOnlyTheAdvisoryInformation() throws Exception
    {
        createAdvisory(ADVISORY_REFERENCE, "DISCLOSABLE");

        assertEquals(PUBLIC_REFERENCE, this.publisher.publish(ADVISORY_REFERENCE));

        XWikiDocument publicDocument = load(PUBLIC_REFERENCE);
        assertFalse(publicDocument.isNew());
        assertEquals("1.1", publicDocument.getVersion());
        assertEquals("Advisory title", publicDocument.getTitle());
        assertEquals(Syntax.XWIKI_2_1, publicDocument.getSyntax());
        assertEquals("Advisory content", publicDocument.getContent());
        assertTrue(publicDocument.isEnforceRequiredRights());
        assertEquals("DISCLOSED", getState(publicDocument));
        assertEquals("CVE-2026-0001", publicDocument
            .getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE)
            .getStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVE_ID));
        List<BaseObject> packages =
            publicDocument.getXObjects(ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        assertEquals(1, packages.size());
        assertEquals("group:artifact",
            packages.get(0).getStringValue(ImpactedPackageClassMandatoryDocumentInitializer.PACKAGE_ID));
        assertTrue(publicDocument.getXObjects(COMMENTS_CLASS).isEmpty());
        assertTrue(publicDocument.getAttachmentList().isEmpty());
        assertNull(publicDocument.getXObject(DisclosedAdvisoryPublisher.REDIRECT_CLASS_REFERENCE));

        // The public content keeps the rights of the user who wrote it, not the ones of the user who discloses it.
        assertEquals(this.reporter, publicDocument.getAuthors().getContentAuthor());
        assertEquals(this.reporter, publicDocument.getAuthors().getEffectiveMetadataAuthor());
        assertEquals(this.discloserUser, publicDocument.getAuthors().getCreator());

        XWikiDocument original = load(ADVISORY_REFERENCE);
        assertEquals("DISCLOSED", getState(original));
        assertEquals("SecurityAdvisoryApplication.DisclosedEntries.GHSA-test",
            original.getXObject(DisclosedAdvisoryPublisher.REDIRECT_CLASS_REFERENCE)
                .getStringValue(DisclosedAdvisoryPublisher.REDIRECT_LOCATION));
        assertEquals("Private discussion",
            original.getXObject(COMMENTS_CLASS).getLargeStringValue("comment"));
        assertEquals(1, original.getAttachmentList().size());
        assertTrue(this.publisher.isPublishedOriginal(original));
    }

    @Test
    void publishResumesWhenThePublicPageAlreadyHoldsTheAdvisory() throws Exception
    {
        createAdvisory(ADVISORY_REFERENCE, "DISCLOSABLE");
        createAdvisory(PUBLIC_REFERENCE, "DISCLOSED");
        String publicVersion = load(PUBLIC_REFERENCE).getVersion();

        assertEquals(PUBLIC_REFERENCE, this.publisher.publish(ADVISORY_REFERENCE));

        assertEquals(publicVersion, load(PUBLIC_REFERENCE).getVersion());
        XWikiDocument original = load(ADVISORY_REFERENCE);
        assertEquals("DISCLOSED", getState(original));
        assertTrue(this.publisher.isPublishedOriginal(original));
    }

    @Test
    void publishAlreadyDisclosedAdvisory() throws Exception
    {
        createAdvisory(ADVISORY_REFERENCE, "DISCLOSED");

        this.publisher.publish(ADVISORY_REFERENCE);

        assertEquals("DISCLOSED", getState(load(PUBLIC_REFERENCE)));
        assertTrue(this.publisher.isPublishedOriginal(load(ADVISORY_REFERENCE)));
    }

    @Test
    void publishRefusesToOverrideAnotherPage() throws Exception
    {
        createAdvisory(ADVISORY_REFERENCE, "DISCLOSABLE");
        XWikiDocument otherPage = new XWikiDocument(PUBLIC_REFERENCE);
        otherPage.setContent("Another page");
        this.oldcore.getSpyXWiki().saveDocument(otherPage, this.oldcore.getXWikiContext());

        SecurityAdvisoryException exception =
            assertThrows(SecurityAdvisoryException.class, () -> this.publisher.publish(ADVISORY_REFERENCE));

        assertEquals("Cannot publish the advisory [xwiki:SecurityAdvisoryApplication.SecurityEntries.GHSA-test]: "
            + "the page [xwiki:SecurityAdvisoryApplication.DisclosedEntries.GHSA-test] already exists and holds another "
            + "advisory.", exception.getMessage());
        assertEquals("Another page", load(PUBLIC_REFERENCE).getContent());
        XWikiDocument original = load(ADVISORY_REFERENCE);
        assertEquals("DISCLOSABLE", getState(original));
        assertFalse(this.publisher.isPublishedOriginal(original));
    }

    @Test
    void publishWithoutEditRightOnThePublicSpace() throws Exception
    {
        createAdvisory(ADVISORY_REFERENCE, "DISCLOSABLE");
        grantEdit(PUBLIC_REFERENCE, false);

        assertFalse(this.publisher.canPublish(ADVISORY_REFERENCE));
        SecurityAdvisoryException exception =
            assertThrows(SecurityAdvisoryException.class, () -> this.publisher.publish(ADVISORY_REFERENCE));

        assertEquals("The current user is not allowed to publish the advisory "
            + "[xwiki:SecurityAdvisoryApplication.SecurityEntries.GHSA-test].", exception.getMessage());
        assertTrue(load(PUBLIC_REFERENCE).isNew());
        assertEquals("DISCLOSABLE", getState(load(ADVISORY_REFERENCE)));
    }

    @Test
    void publishWithoutEditRightOnTheAdvisory() throws Exception
    {
        createAdvisory(ADVISORY_REFERENCE, "DISCLOSABLE");
        grantEdit(ADVISORY_REFERENCE, false);

        assertFalse(this.publisher.canPublish(ADVISORY_REFERENCE));
        assertThrows(SecurityAdvisoryException.class, () -> this.publisher.publish(ADVISORY_REFERENCE));
        assertTrue(load(PUBLIC_REFERENCE).isNew());
    }

    @Test
    void publishAdvisoryNotYetDisclosable() throws Exception
    {
        createAdvisory(ADVISORY_REFERENCE, "ANNOUNCED");

        SecurityAdvisoryException exception =
            assertThrows(SecurityAdvisoryException.class, () -> this.publisher.publish(ADVISORY_REFERENCE));

        assertEquals("The advisory [xwiki:SecurityAdvisoryApplication.SecurityEntries.GHSA-test] cannot be published "
            + "in state [ANNOUNCED].", exception.getMessage());
        assertTrue(load(PUBLIC_REFERENCE).isNew());
    }

    @Test
    void publishAlreadyPublishedAdvisory() throws Exception
    {
        createAdvisory(ADVISORY_REFERENCE, "DISCLOSABLE");
        this.publisher.publish(ADVISORY_REFERENCE);

        SecurityAdvisoryException exception =
            assertThrows(SecurityAdvisoryException.class, () -> this.publisher.publish(ADVISORY_REFERENCE));

        assertEquals("The advisory [xwiki:SecurityAdvisoryApplication.SecurityEntries.GHSA-test] is already published.",
            exception.getMessage());
    }

    @Test
    void publishAdvisoryFromThePublicSpace() throws Exception
    {
        DocumentReference otherPublicReference = new DocumentReference("Other", PUBLIC_SPACE);
        createAdvisory(otherPublicReference, "DISCLOSABLE");
        grantEdit(otherPublicReference, true);

        SecurityAdvisoryException exception =
            assertThrows(SecurityAdvisoryException.class, () -> this.publisher.publish(otherPublicReference));

        assertEquals("The advisory [xwiki:SecurityAdvisoryApplication.DisclosedEntries.Other] is already located in "
            + "the public data space.", exception.getMessage());
    }

    @Test
    void publishPageWithoutAdvisory() throws Exception
    {
        XWikiDocument page = new XWikiDocument(ADVISORY_REFERENCE);
        this.oldcore.getSpyXWiki().saveDocument(page, this.oldcore.getXWikiContext());

        SecurityAdvisoryException exception =
            assertThrows(SecurityAdvisoryException.class, () -> this.publisher.publish(ADVISORY_REFERENCE));

        assertEquals("The page [xwiki:SecurityAdvisoryApplication.SecurityEntries.GHSA-test] does not hold any "
            + "advisory.", exception.getMessage());
    }

    @Test
    void getUnpublishedDisclosedAdvisories() throws Exception
    {
        DocumentReference unpublished = new DocumentReference("Unpublished", SECURITY_SPACE);
        createAdvisory(unpublished, "DISCLOSED");
        createAdvisory(ADVISORY_REFERENCE, "DISCLOSABLE");
        this.publisher.publish(ADVISORY_REFERENCE);

        Query query = mock(Query.class);
        when(this.queryManager.createQuery(anyString(), any())).thenReturn(query);
        when(query.bindValue("status", "DISCLOSED")).thenReturn(query);
        when(query.execute()).thenReturn(List.of(
            "xwiki:SecurityAdvisoryApplication.SecurityEntries.Unpublished",
            "xwiki:SecurityAdvisoryApplication.SecurityEntries.GHSA-test",
            "xwiki:SecurityAdvisoryApplication.DisclosedEntries.GHSA-test"));

        assertEquals(List.of(unpublished), this.publisher.getUnpublishedDisclosedAdvisories());
    }
}
