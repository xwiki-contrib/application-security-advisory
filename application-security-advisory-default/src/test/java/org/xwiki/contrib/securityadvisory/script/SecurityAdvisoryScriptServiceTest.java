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
package org.xwiki.contrib.securityadvisory.script;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.securityadvisory.ExternalUser;
import org.xwiki.contrib.securityadvisory.internal.assignee.AssigneeResolutionJobManager;
import org.xwiki.contrib.securityadvisory.internal.assignee.AssigneeResolver;
import org.xwiki.contrib.securityadvisory.internal.assignee.ExternalUserMappingStore;
import org.xwiki.job.event.status.JobStatus;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.security.authorization.AccessDeniedException;
import org.xwiki.security.authorization.Right;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceResolver;

import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import jakarta.inject.Named;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for the external user mapping methods of {@link SecurityAdvisoryScriptService}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class SecurityAdvisoryScriptServiceTest
{
    private static final ExternalUser SURLI = new ExternalUser("github", "1478232", "surli");

    private static final DocumentReference USER_DOCUMENT = new DocumentReference("xwiki", "XWiki", "surli");

    private static final DocumentReference ADMIN_DOCUMENT = new DocumentReference("xwiki", "XWiki", "Admin");

    private static final DocumentReference ADVISORY_REFERENCE =
        new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "SecurityEntries"), "GHSA-test");

    @InjectMockComponents
    private SecurityAdvisoryScriptService scriptService;

    @MockComponent
    private AssigneeResolver assigneeResolver;

    @MockComponent
    private AssigneeResolutionJobManager jobManager;

    @MockComponent
    private ExternalUserMappingStore externalUserMappingStore;

    @MockComponent
    @Named("document")
    private UserReferenceResolver<DocumentReference> userReferenceResolver;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    private WikiReference wikiReference;

    private UserReference user;

    private UserReference admin;

    @BeforeEach
    void setUp()
    {
        this.wikiReference = this.oldcore.getXWikiContext().getWikiReference();
        this.oldcore.getXWikiContext().setUserReference(ADMIN_DOCUMENT);
        this.user = mock(UserReference.class);
        this.admin = mock(UserReference.class);
        when(this.userReferenceResolver.resolve(USER_DOCUMENT)).thenReturn(this.user);
        when(this.userReferenceResolver.resolve(ADMIN_DOCUMENT)).thenReturn(this.admin);
    }

    @Test
    void mappingRequiresAdmin() throws Exception
    {
        doThrow(AccessDeniedException.class).when(this.oldcore.getMockContextualAuthorizationManager())
            .checkAccess(Right.ADMIN, this.wikiReference);

        assertThrows(AccessDeniedException.class, () -> this.scriptService.linkExternalUser(SURLI.hint(), SURLI.id(),
            SURLI.login(), USER_DOCUMENT, ADVISORY_REFERENCE));
        assertThrows(AccessDeniedException.class,
            () -> this.scriptService.setExternalUserArchived(SURLI.hint(), SURLI.id(), SURLI.login(), true));
        assertThrows(AccessDeniedException.class, () -> this.scriptService.startAssigneeResolution());

        verifyNoInteractions(this.externalUserMappingStore, this.assigneeResolver, this.jobManager);
    }

    @Test
    void linkExternalUser() throws Exception
    {
        this.scriptService.linkExternalUser(SURLI.hint(), SURLI.id(), SURLI.login(), USER_DOCUMENT,
            ADVISORY_REFERENCE);

        verify(this.externalUserMappingStore).setMapping(SURLI, this.user);
        verify(this.assigneeResolver).resolveAssignee(ADVISORY_REFERENCE, this.admin);
    }

    @Test
    void linkExternalUserWithoutAdvisory() throws Exception
    {
        this.scriptService.linkExternalUser(SURLI.hint(), SURLI.id(), SURLI.login(), USER_DOCUMENT, null);

        verify(this.externalUserMappingStore).setMapping(SURLI, this.user);
        verifyNoInteractions(this.assigneeResolver);
    }

    @Test
    void setExternalUserArchived() throws Exception
    {
        this.scriptService.setExternalUserArchived(SURLI.hint(), SURLI.id(), SURLI.login(), true);

        verify(this.externalUserMappingStore).setArchived(SURLI, true);
    }

    @Test
    void startAssigneeResolution() throws Exception
    {
        JobStatus jobStatus = mock(JobStatus.class);
        when(this.jobManager.startResolution(ADMIN_DOCUMENT)).thenReturn(jobStatus);

        assertSame(jobStatus, this.scriptService.startAssigneeResolution());
    }

    @Test
    void readMethodsRequireRights() throws Exception
    {
        when(this.assigneeResolver.countUnassignedAdvisories(any())).thenReturn(2);

        assertEquals(0, this.scriptService.countUnassignedAdvisories(SURLI.hint(), SURLI.id()));
        assertEquals(List.of(), this.scriptService.getUnmappedExternalUsers(ADVISORY_REFERENCE));

        when(this.oldcore.getMockContextualAuthorizationManager().hasAccess(Right.ADMIN, this.wikiReference))
            .thenReturn(true);
        assertEquals(2, this.scriptService.countUnassignedAdvisories(SURLI.hint(), SURLI.id()));
    }
}
