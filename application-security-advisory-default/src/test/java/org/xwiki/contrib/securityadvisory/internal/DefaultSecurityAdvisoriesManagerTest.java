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
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.event.AdvisoryStateChangedEvent;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.observation.ObservationManager;
import org.xwiki.query.Query;
import org.xwiki.query.QueryManager;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

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

    private static final String ADVISORY_LINK = "https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-test";

    @InjectMockComponents
    private DefaultSecurityAdvisoriesManager manager;

    @MockComponent
    private DisclosedAdvisoryPublisher publisher;

    @MockComponent
    private QueryManager queryManager;

    @MockComponent
    private ObservationManager observationManager;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

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
