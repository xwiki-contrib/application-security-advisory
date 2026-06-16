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

import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.objects.classes.ComputedFieldClass;
import com.xpn.xwiki.objects.classes.StaticListClass;

public class SecurityAdvisoriesMandatoryDocumentInitializer extends AbstractMandatoryClassInitializer
{
    public static final String FIELD_ADVISORY_LINK = "advisoryLink";
    public static final String FIELD_CVSS = "cvss";
    public static final String FIELD_CVSS_SCORE = "cvssScore";

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
     * Field containing the issue tracker tickets.
     */
    public static final String FIELD_TICKETS = "jiraTickets";

    /**
     * Field containing the CVE identifier.
     */
    public static final String FIELD_CVE_ID = "cveId";

    /**
     * Reference of the class.
     */
    public static final EntityReference CLASS_REFERENCE =
        new LocalDocumentReference(List.of("SecurityAdvisoryApplication", "Code"), "SecurityAdvisoryApplicationClass");

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
        xclass.addStaticListField(FIELD_TICKETS, FIELD_TICKETS, 1, true, null,
            StaticListClass.DISPLAYTYPE_INPUT, ",");
        xclass.addStaticListField(FIELD_PRODUCT, FIELD_PRODUCT, 1, false, null,
            StaticListClass.DISPLAYTYPE_INPUT, ",");
        xclass.addStaticListField(FIELD_STATE, FIELD_STATE, 1, false,
            Stream.of(SecurityAdvisory.State.values())
                .map(state -> String.format("%s=%s", state.name(), state.name().toLowerCase()))
                .collect(Collectors.joining("|")),
            StaticListClass.DISPLAYTYPE_SELECT, ",");

        ComputedFieldClass titleField = new ComputedFieldClass();
        titleField.setCustomDisplay("{{include reference=\"AppWithinMinutes.Title\"/}}");
        titleField.setName("title1");
        titleField.setPrettyName("Title of the advisory");
        xclass.addField("title1", titleField);

        ComputedFieldClass contentField = new ComputedFieldClass();
        contentField.setCustomDisplay("{{include reference=\"AppWithinMinutes.Content\"/}}");
        contentField.setName("description");
        contentField.setPrettyName("description");
        contentField.setHint("Full content of the advisory");
        xclass.addField("description", contentField);
    }
}
