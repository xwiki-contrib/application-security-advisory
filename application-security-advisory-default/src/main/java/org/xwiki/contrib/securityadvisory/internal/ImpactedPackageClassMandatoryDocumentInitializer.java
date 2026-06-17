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

import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.objects.classes.ListClass;

import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Initializer for the xclass holding impacted packages information.
 *
 * @version $Id$
 * @since 2.0
 */
@Component
@Singleton
@Named("ImpactedPackageClassMandatoryDocumentInitializer")
public class ImpactedPackageClassMandatoryDocumentInitializer extends AbstractMandatoryClassInitializer
{
    /**
     * Identifier of the impacted package.
     */
    public static final String PACKAGE_ID = "packageId";

    /**
     * List of Ranges of impacted versions.
     */
    public static final String VULNERABLE_VERSION_RANGE  = "vulnerableVersionRange";

    /**
     * List of patched versions.
     */
    public static final String PATCHED_VERSIONS = "patchedVersions";

    /**
     * Ecosystem of the package (e.g. Maven or NPM)
     */
    public static final String ECOSYSTEM = "ecosystem";

    /**
     * Reference of the xclass.
     */
    public static final EntityReference CLASS_REFERENCE =
        new LocalDocumentReference(List.of("SecurityAdvisoryApplication", "Code"),
            "SecurityAdvisoryImpactedPackageClass");

    /**
     * Default constructor.
     */
    public ImpactedPackageClassMandatoryDocumentInitializer()
    {
        super(CLASS_REFERENCE);
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        xclass.addTextField(PACKAGE_ID, PACKAGE_ID, 255);
        xclass.addStaticListField(VULNERABLE_VERSION_RANGE, VULNERABLE_VERSION_RANGE, 1, true, false, null,
            ListClass.DISPLAYTYPE_INPUT, ListClass.DEFAULT_SEPARATOR, null, ListClass.FREE_TEXT_ALLOWED, false);
        xclass.addStaticListField(PATCHED_VERSIONS, PATCHED_VERSIONS, 1, true, false, null,
            ListClass.DISPLAYTYPE_INPUT, ListClass.DEFAULT_SEPARATOR, null, ListClass.FREE_TEXT_ALLOWED, false);
        xclass.addTextField(ECOSYSTEM, ECOSYSTEM, 255);
    }
}
