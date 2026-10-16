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

import org.apache.commons.lang3.StringUtils;
import org.xwiki.bridge.event.DocumentCreatingEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryApplicationClassMandatoryDocumentInitializer;
import org.xwiki.observation.event.AbstractLocalEventListener;
import org.xwiki.observation.event.Event;
import org.xwiki.user.UserReference;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Listener assigning an advisory created by hand to its creator. Imported advisories are not concerned: their
 * assignee comes from the mapping of their external users, and their creator is the technical importer user.
 *
 * @version $Id$
 * @since 2.2.2
 */
@Component
@Singleton
@Named(CreatorAssigneeListener.NAME)
public class CreatorAssigneeListener extends AbstractLocalEventListener
{
    static final String NAME = "org.xwiki.contrib.securityadvisory.internal.assignee.CreatorAssigneeListener";

    @Inject
    private SecurityAdvisoryConfiguration configuration;

    @Inject
    private UserPropertyConverter userPropertyConverter;

    /**
     * Default constructor.
     */
    public CreatorAssigneeListener()
    {
        super(NAME, new DocumentCreatingEvent());
    }

    @Override
    public void processLocalEvent(Event event, Object source, Object data)
    {
        if (source instanceof XWikiDocument document) {
            BaseObject advisoryObject =
                document.getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE);
            UserReference creator = document.getAuthors().getCreator();
            if (advisoryObject != null && creator != null && shouldAssignCreator(document, advisoryObject, creator)) {
                String assignee = this.userPropertyConverter.serialize(creator, document.getDocumentReference());
                if (assignee != null) {
                    advisoryObject.setLargeStringValue(
                        SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE, assignee);
                }
            }
        }
    }

    private boolean shouldAssignCreator(XWikiDocument document, BaseObject advisoryObject, UserReference creator)
    {
        boolean isImported =
            !document.getXObjects(ExternalUserClassMandatoryDocumentInitializer.CLASS_REFERENCE).isEmpty()
                || creator.equals(this.configuration.getAdvisoryImporterUser());
        return !isImported && StringUtils.isBlank(advisoryObject.getLargeStringValue(
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE));
    }
}
