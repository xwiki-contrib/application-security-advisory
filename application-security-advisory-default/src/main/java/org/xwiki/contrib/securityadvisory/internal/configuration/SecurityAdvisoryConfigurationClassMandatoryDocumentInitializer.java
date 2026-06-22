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
package org.xwiki.contrib.securityadvisory.internal.configuration;

import java.util.List;

import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.objects.classes.ListClass;
import com.xpn.xwiki.objects.classes.NumberClass;
import com.xpn.xwiki.objects.meta.PasswordMetaClass;

import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Mandatory class initializer for SecurityAdvisoryConfigurationClass.
 *
 * @version $Id$
 * @since 2.0
 */
@Component
@Singleton
@Named("SecurityAdvisoryConfigurationClassMandatoryDocumentInitializer")
public class SecurityAdvisoryConfigurationClassMandatoryDocumentInitializer extends AbstractMandatoryClassInitializer
{
    /**
     * Field for holding embargo duration unit.
     */
    public static final String EMBARGO_DURATION_UNIT = "embargoDurationUnit";

    /**
     * Field for holding default embargo duration.
     */
    public static final String DEFAULT_EMBARGO_DURATION = "defaultEmbargoDuration";

    /**
     * Field for holding security group.
     */
    public static final String SECURITY_GROUP = "securityGroup";

    /**
     * Field for holding data space.
     */
    public static final String DATA_SPACE = "dataSpace";

    /**
     * Field for holding importer user.
     */
    public static final String IMPORTER_USER = "importerUser";

    /**
     * Field for holding Github token.
     */
    public static final String GITHUB_TOKEN = "githubToken";

    /**
     * Field for holding Github repositories slug to import.
     */
    public static final String GITHUB_REPOSITORIES_SLUG = "githubRepositoriesSlug";

    /**
     * Reference of the xclass.
     */
    public static final EntityReference CLASS_REFERENCE =
        new LocalDocumentReference(List.of("SecurityAdvisoryApplication", "Code"),
            "SecurityAdvisoryConfigurationClass");

    /**
     * Default constructor.
     */
    public SecurityAdvisoryConfigurationClassMandatoryDocumentInitializer()
    {
        super(CLASS_REFERENCE);
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        xclass.addTextField(EMBARGO_DURATION_UNIT, EMBARGO_DURATION_UNIT, 255);
        xclass.addGroupsField(SECURITY_GROUP, SECURITY_GROUP);
        xclass.addNumberField(DEFAULT_EMBARGO_DURATION, DEFAULT_EMBARGO_DURATION, 20, NumberClass.TYPE_INTEGER);
        xclass.addTextField(DATA_SPACE, DATA_SPACE, 255);
        xclass.addUsersField(IMPORTER_USER, IMPORTER_USER);
        xclass.addPasswordField(GITHUB_TOKEN, GITHUB_TOKEN, 255, PasswordMetaClass.CLEAR);
        xclass.addStaticListField(GITHUB_REPOSITORIES_SLUG, GITHUB_REPOSITORIES_SLUG, 1, true, false, null,
            ListClass.DISPLAYTYPE_INPUT, null, null, ListClass.FREE_TEXT_ALLOWED, false);
    }
}
