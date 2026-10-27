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

import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.doc.AbstractMandatoryDocumentInitializer;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Restricts the space holding the external users and their mapping to administrators: the mapping decides who is in
 * charge of embargoed advisories. The rights are only set when the space has none, so that they can be customized.
 *
 * @version $Id$
 * @since 2.2.2
 */
@Component
@Singleton
@Named("SecurityAdvisoryApplication.ExternalUsers.WebPreferences")
public class ExternalUsersRightsInitializer extends AbstractMandatoryDocumentInitializer
{
    private static final LocalDocumentReference RIGHTS_CLASS =
        new LocalDocumentReference(XWiki.SYSTEM_SPACE, "XWikiGlobalRights");

    /**
     * Default constructor.
     */
    public ExternalUsersRightsInitializer()
    {
        super(new LocalDocumentReference(ExternalUserMappingStore.SPACE_NAMES, "WebPreferences"));
    }

    @Override
    public boolean updateDocument(XWikiDocument document)
    {
        boolean needsUpdate = super.updateDocument(document);
        if (document.getXObjects(RIGHTS_CLASS).isEmpty()) {
            BaseObject rightsObject = new BaseObject();
            rightsObject.setXClassReference(RIGHTS_CLASS);
            rightsObject.setLargeStringValue("groups", "XWiki.XWikiAdminGroup");
            rightsObject.setLargeStringValue("users", "");
            rightsObject.setStringValue("levels", "view,edit");
            rightsObject.setIntValue("allow", 1);
            document.addXObject(rightsObject);
            needsUpdate = true;
        }
        return needsUpdate;
    }
}
