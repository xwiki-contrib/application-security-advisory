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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.objects.classes.ListClass;
import com.xpn.xwiki.objects.classes.StaticListClass;

import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Initializer for the xclass holding security advisory informations.
 *
 * @version $Id$
 * @since 2.0
 */
@Component
@Singleton
@Named("SecurityAdvisoriesMandatoryDocumentInitializer")
public class SecurityAdvisoriesMandatoryDocumentInitializer extends AbstractMandatoryClassInitializer
{
    /**
     * Link for the external advisory.
     */
    public static final String FIELD_ADVISORY_LINK = "advisoryLink";

    /**
     * Contains CVSS vector.
     */
    public static final String FIELD_CVSS = "cvss";

    /**
     * Contains CVSS score.
     */
    public static final String FIELD_CVSS_SCORE = "cvssScore";

    /**
     * Product the advisory refers to.
     */
    public static final String FIELD_PRODUCT = "product";

    /**
     * Field containing the state of the advisory.
     */
    public static final String FIELD_STATE = "status";

    /**
     * Field containing the embargo date.
     */
    public static final String FIELD_EMBARGO_DATE = "embargoDate";

    /**
     * Field containing the flag to know if the embargo date should be computed or not.
     */
    public static final String FIELD_COMPUTE_EMBARGO_DATE = "computeEmbargo";

    /**
     * Field containing the CVE identifier.
     */
    public static final String FIELD_CVE_ID = "cveId";

    /**
     * Flag to allow overriding or not the advisory when importing data.
     */
    public static final String PREVENT_OVERRIDE = "preventOverride";

    /**
     * Reference of the class.
     */
    public static final EntityReference CLASS_REFERENCE =
        new LocalDocumentReference(List.of("SecurityAdvisoryApplication", "Code"), "SecurityAdvisoryApplicationClass");

    /**
     * Default constructor.
     */
    public SecurityAdvisoriesMandatoryDocumentInitializer()
    {
        super(CLASS_REFERENCE);
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        xclass.addTextField(FIELD_ADVISORY_LINK, FIELD_ADVISORY_LINK, 255);
        xclass.addTextField(FIELD_CVSS, FIELD_CVSS, 255);
        xclass.addTextField(FIELD_STATE, FIELD_STATE, 255);
        xclass.addBooleanField(FIELD_COMPUTE_EMBARGO_DATE, FIELD_COMPUTE_EMBARGO_DATE);
        xclass.addDateField(FIELD_EMBARGO_DATE, FIELD_EMBARGO_DATE);
        xclass.addStaticListField(FIELD_PRODUCT, FIELD_PRODUCT, 1, false, null,
            StaticListClass.DISPLAYTYPE_INPUT, ListClass.DEFAULT_SEPARATOR);
        xclass.addStaticListField(FIELD_STATE, FIELD_STATE, 1, false,
            Stream.of(SecurityAdvisory.State.values())
                .map(state -> String.format("%s=%s", state.name(), state.name().toLowerCase()))
                .collect(Collectors.joining(ListClass.DEFAULT_SEPARATOR)),
            StaticListClass.DISPLAYTYPE_SELECT, ListClass.DEFAULT_SEPARATOR);
    }
}
