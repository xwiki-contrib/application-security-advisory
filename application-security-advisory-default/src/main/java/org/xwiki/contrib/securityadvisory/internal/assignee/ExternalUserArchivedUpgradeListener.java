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

import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.extension.InstalledExtension;
import org.xwiki.extension.event.ExtensionUpgradedEvent;
import org.xwiki.extension.version.VersionConstraint;
import org.xwiki.extension.version.internal.DefaultVersionConstraint;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;
import org.xwiki.wiki.manager.WikiManagerException;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Initializes the missing {@code archived} value of the external user pages when the application is upgraded from
 * version 2.3.0. The pages registered by the advisory import of this version have no {@code archived} value, so the
 * administration filter listing the external users that are not archived doesn't match them. The previous versions
 * didn't register external users, and the next ones initialize the value when saving the page.
 *
 * @version $Id$
 * @since 2.3.1
 */
@Component
@Singleton
@Named(ExternalUserArchivedUpgradeListener.NAME)
public class ExternalUserArchivedUpgradeListener extends AbstractEventListener
{
    /**
     * The name of the listener.
     */
    public static final String NAME = "ExternalUserArchivedUpgradeListener";

    /**
     * The identifier of the extension holding the administration listing the external users.
     */
    static final String UI_EXTENSION_ID = "org.xwiki.contrib.security-advisory:application-security-advisory-ui";

    /**
     * The versions registering external user pages without {@code archived} value.
     */
    private static final VersionConstraint MISSING_ARCHIVED_VERSIONS = new DefaultVersionConstraint("[2.3.0,2.3.1)");

    private static final String WIKI_NAMESPACE_PREFIX = "wiki:";

    private static final String MISSING_ARCHIVED_STATEMENT = "select distinct obj.name from BaseObject obj "
        + "where obj.className = :className and not exists (select prop.id.id from IntegerProperty prop "
        + "where prop.id.id = obj.id and prop.id.name = :archived and prop.value is not null)";

    @Inject
    private QueryManager queryManager;

    @Inject
    @Named("local")
    private EntityReferenceSerializer<String> localSerializer;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    private WikiDescriptorManager wikiDescriptorManager;

    @Inject
    private ExternalUserMappingStore externalUserMappingStore;

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public ExternalUserArchivedUpgradeListener()
    {
        super(NAME, new ExtensionUpgradedEvent(UI_EXTENSION_ID));
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        if (!isUpgradedFromMissingArchivedVersion(data)) {
            return;
        }
        String namespace = ((ExtensionUpgradedEvent) event).getNamespace();
        if (namespace == null) {
            // The application is installed on the root namespace, i.e. on all the wikis of the farm.
            try {
                for (String wikiId : this.wikiDescriptorManager.getAllIds()) {
                    initializeArchived(wikiId);
                }
            } catch (WikiManagerException e) {
                this.logger.warn("Failed to list the wikis to initialize the archived value of the external users.",
                    e);
            }
        } else if (namespace.startsWith(WIKI_NAMESPACE_PREFIX)) {
            initializeArchived(namespace.substring(WIKI_NAMESPACE_PREFIX.length()));
        }
    }

    /**
     * @param previousExtensions the extensions replaced by the upgrade, as provided by {@link ExtensionUpgradedEvent}
     */
    private boolean isUpgradedFromMissingArchivedVersion(Object previousExtensions)
    {
        return previousExtensions instanceof Collection<?> extensions && extensions.stream()
            .filter(InstalledExtension.class::isInstance)
            .map(InstalledExtension.class::cast)
            .filter(extension -> UI_EXTENSION_ID.equals(extension.getId().getId()))
            .anyMatch(extension -> MISSING_ARCHIVED_VERSIONS.containsVersion(extension.getId().getVersion()));
    }

    private void initializeArchived(String wikiId)
    {
        WikiReference wikiReference = new WikiReference(wikiId);
        String className =
            this.localSerializer.serialize(ExternalUserMappingClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        List<String> names;
        try {
            names = this.queryManager.createQuery(MISSING_ARCHIVED_STATEMENT, Query.HQL)
                .bindValue("className", className)
                .bindValue("archived", ExternalUserMappingClassMandatoryDocumentInitializer.ARCHIVED)
                .setWiki(wikiId)
                .execute();
        } catch (QueryException e) {
            this.logger.warn("Failed to find the external users without archived value in the wiki [{}].", wikiId, e);
            return;
        }
        for (String name : names) {
            DocumentReference reference = this.documentReferenceResolver.resolve(name, wikiReference);
            try {
                this.externalUserMappingStore.initializeArchived(reference);
            } catch (Exception e) {
                this.logger.warn("Failed to initialize the archived value of the external user page [{}].",
                    reference, e);
            }
        }
    }
}
