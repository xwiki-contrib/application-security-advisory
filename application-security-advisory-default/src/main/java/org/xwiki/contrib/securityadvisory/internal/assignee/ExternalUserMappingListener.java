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

import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.bridge.event.DocumentCreatedEvent;
import org.xwiki.bridge.event.DocumentUpdatedEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.job.JobException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.observation.event.AbstractLocalEventListener;
import org.xwiki.observation.event.Event;
import org.xwiki.user.UserReferenceSerializer;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Listener assigning the advisories without assignee as soon as an external user is mapped to an XWiki user, whatever
 * the way the mapping is saved (from an advisory, or from the live data of the administration).
 *
 * @version $Id$
 * @since 2.2.2
 */
@Component
@Singleton
@Named(ExternalUserMappingListener.NAME)
public class ExternalUserMappingListener extends AbstractLocalEventListener
{
    static final String NAME = "org.xwiki.contrib.securityadvisory.internal.assignee.ExternalUserMappingListener";

    @Inject
    private AssigneeResolutionJobManager jobManager;

    @Inject
    @Named("document")
    private UserReferenceSerializer<DocumentReference> userReferenceSerializer;

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public ExternalUserMappingListener()
    {
        super(NAME, new DocumentCreatedEvent(), new DocumentUpdatedEvent());
    }

    @Override
    public void processLocalEvent(Event event, Object source, Object data)
    {
        if (source instanceof XWikiDocument document) {
            String user = getUser(document);
            if (StringUtils.isNotBlank(user) && !Objects.equals(user, getUser(document.getOriginalDocument()))) {
                DocumentReference author =
                    this.userReferenceSerializer.serialize(document.getAuthors().getEffectiveMetadataAuthor());
                try {
                    this.jobManager.startResolution(author);
                } catch (JobException e) {
                    this.logger.error("Failed to start the assignment of the advisories after the mapping of [{}].",
                        document.getDocumentReference(), e);
                }
            }
        }
    }

    private String getUser(XWikiDocument document)
    {
        BaseObject mappingObject = (document != null)
            ? document.getXObject(ExternalUserMappingClassMandatoryDocumentInitializer.CLASS_REFERENCE) : null;
        return (mappingObject != null)
            ? mappingObject.getLargeStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.USER) : null;
    }
}
