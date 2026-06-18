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

import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Mandatory class initializer for RepositoryMappingClass.
 *
 * @version $Id$
 * @since 2.0
 */
@Component
@Singleton
@Named("RepositoryMappingClassMandatoryDocumentInitializer")
public class RepositoryMappingClassMandatoryDocumentInitializer extends AbstractMandatoryClassInitializer
{
    /**
     * Field for holding the repository slug.
     */
    public static final String REPOSITORY_NAME = "repository";

    /**
     * Field for holding the project name.
     */
    public static final String PROJECT_NAME = "project";

    /**
     * Reference of the xclass.
     */
    public static final EntityReference CLASS_REFERENCE =
        new LocalDocumentReference(List.of("SecurityAdvisoryApplication", "Code"), "RepositoryMappingClass");

    /**
     * Default constructor.
     */
    public RepositoryMappingClassMandatoryDocumentInitializer()
    {
        super(CLASS_REFERENCE);
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        xclass.addTextField(REPOSITORY_NAME, REPOSITORY_NAME, 255);
        xclass.addTextField(PROJECT_NAME, PROJECT_NAME, 255);
    }
}
