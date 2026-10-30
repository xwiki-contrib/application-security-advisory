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
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryApplicationClassMandatoryDocumentInitializer;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;

import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Mandatory class initializer for the class holding, in an advisory document, the users of the external system the
 * advisory was imported from. The objects are ordered by priority for being the assignee of the advisory.
 *
 * @version $Id$
 * @since 2.3.0
 */
@Component
@Singleton
@Named("ExternalUserClassMandatoryDocumentInitializer")
public class ExternalUserClassMandatoryDocumentInitializer extends AbstractMandatoryClassInitializer
{
    /**
     * Hint of the external system the user belongs to.
     */
    public static final String HINT = "hint";

    /**
     * Stable identifier of the user in the external system.
     */
    public static final String EXTERNAL_ID = "externalId";

    /**
     * Login of the user in the external system.
     */
    public static final String LOGIN = "login";

    /**
     * Reference of the xclass.
     */
    public static final EntityReference CLASS_REFERENCE =
        new LocalDocumentReference(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CODE_SPACE_LIST,
            "SecurityAdvisoryExternalUserClass");

    /**
     * Default constructor.
     */
    public ExternalUserClassMandatoryDocumentInitializer()
    {
        super(CLASS_REFERENCE);
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        xclass.addTextField(HINT, HINT, 255);
        xclass.addTextField(EXTERNAL_ID, EXTERNAL_ID, 255);
        xclass.addTextField(LOGIN, LOGIN, 255);
    }
}
