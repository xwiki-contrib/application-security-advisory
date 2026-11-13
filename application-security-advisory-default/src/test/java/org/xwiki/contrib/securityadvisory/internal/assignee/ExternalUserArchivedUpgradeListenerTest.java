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
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.extension.ExtensionId;
import org.xwiki.extension.InstalledExtension;
import org.xwiki.extension.event.ExtensionUpgradedEvent;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryManager;
import org.xwiki.test.LogLevel;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import jakarta.inject.Named;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link ExternalUserArchivedUpgradeListener}.
 *
 * @version $Id$
 */
@ComponentTest
class ExternalUserArchivedUpgradeListenerTest
{
    private static final ExtensionId UI_EXTENSION =
        new ExtensionId(ExternalUserArchivedUpgradeListener.UI_EXTENSION_ID, "2.3.1");

    private static final String PAGE_NAME = "SecurityAdvisoryApplication.ExternalUsers.github-42";

    private static final DocumentReference MAIN_PAGE =
        new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "ExternalUsers"), "github-42");

    private static final DocumentReference SUB_PAGE =
        new DocumentReference("sub", List.of("SecurityAdvisoryApplication", "ExternalUsers"), "github-42");

    @RegisterExtension
    private LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.WARN);

    @InjectMockComponents
    private ExternalUserArchivedUpgradeListener listener;

    @MockComponent
    private QueryManager queryManager;

    @MockComponent
    @Named("local")
    private EntityReferenceSerializer<String> localSerializer;

    @MockComponent
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @MockComponent
    private WikiDescriptorManager wikiDescriptorManager;

    @MockComponent
    private ExternalUserMappingStore externalUserMappingStore;

    @BeforeEach
    void setUp() throws Exception
    {
        when(this.localSerializer.serialize(ExternalUserMappingClassMandatoryDocumentInitializer.CLASS_REFERENCE))
            .thenReturn("SecurityAdvisoryApplication.Code.ExternalUserMappingClass");
        when(this.wikiDescriptorManager.getAllIds()).thenReturn(List.of("xwiki", "sub"));
        // Each wiki has one external user page without archived value.
        for (Map.Entry<String, DocumentReference> entry : Map.of("xwiki", MAIN_PAGE, "sub", SUB_PAGE).entrySet()) {
            when(this.documentReferenceResolver.resolve(PAGE_NAME, new WikiReference(entry.getKey())))
                .thenReturn(entry.getValue());
        }
        Query query = mock(Query.class);
        when(this.queryManager.createQuery(anyString(), any())).thenReturn(query);
        when(query.bindValue(anyString(), any())).thenReturn(query);
        when(query.setWiki(anyString())).thenReturn(query);
        when(query.execute()).thenReturn(List.of(PAGE_NAME));
    }

    private static List<InstalledExtension> previousExtensions(String version)
    {
        InstalledExtension previous = mock(InstalledExtension.class);
        when(previous.getId())
            .thenReturn(new ExtensionId(ExternalUserArchivedUpgradeListener.UI_EXTENSION_ID, version));
        return List.of(previous);
    }

    @Test
    void upgradeOnWiki() throws Exception
    {
        this.listener.onEvent(new ExtensionUpgradedEvent(UI_EXTENSION, "wiki:sub"), null,
            previousExtensions("2.3.0"));

        verify(this.externalUserMappingStore).initializeArchived(SUB_PAGE);
        verify(this.externalUserMappingStore, never()).initializeArchived(MAIN_PAGE);
    }

    @Test
    void upgradeOnFarm() throws Exception
    {
        // A failure on a wiki doesn't prevent initializing the other wikis.
        when(this.externalUserMappingStore.initializeArchived(MAIN_PAGE))
            .thenThrow(new SecurityAdvisoryException("Save failed"));

        this.listener.onEvent(new ExtensionUpgradedEvent(UI_EXTENSION, null), null, previousExtensions("2.3.0"));

        verify(this.externalUserMappingStore).initializeArchived(SUB_PAGE);
        assertEquals("Failed to initialize the archived value of the external user page "
            + "[xwiki:SecurityAdvisoryApplication.ExternalUsers.github-42].", this.logCapture.getMessage(0));
    }

    @Test
    void upgradeFromOtherVersion()
    {
        // Only version 2.3.0 registered external user pages without archived value.
        for (String version : List.of("2.2.0", "2.3.1", "2.4.0")) {
            this.listener.onEvent(new ExtensionUpgradedEvent(UI_EXTENSION, "wiki:sub"), null,
                previousExtensions(version));
        }

        verifyNoInteractions(this.queryManager, this.externalUserMappingStore);
    }
}
