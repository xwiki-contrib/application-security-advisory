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
import org.xwiki.sheet.SheetBinder;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.objects.classes.ComputedFieldClass;
import com.xpn.xwiki.objects.classes.ListClass;
import com.xpn.xwiki.objects.classes.NumberClass;
import com.xpn.xwiki.objects.classes.StaticListClass;

import jakarta.inject.Inject;
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
@Named("SecurityAdvisoryApplicationClassMandatoryDocumentInitializer")
public class SecurityAdvisoryApplicationClassMandatoryDocumentInitializer extends AbstractMandatoryClassInitializer
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
     * Space where the UI code is located.
     */
    public static final List<String> CODE_SPACE_LIST = List.of("SecurityAdvisoryApplication", "Code");

    /**
     * Reference of the class.
     */
    public static final EntityReference CLASS_REFERENCE =
        new LocalDocumentReference(CODE_SPACE_LIST, "SecurityAdvisoryApplicationClass");

    private static final String CHECKBOX_INPUT = "checkbox";

    private static final LocalDocumentReference SHEET_REFERENCE =
        new LocalDocumentReference(CODE_SPACE_LIST, "SecurityAdvisoryApplicationSheet");

    private static final LocalDocumentReference CLASSSHEET_REFERENCE =
        new LocalDocumentReference(XWiki.SYSTEM_SPACE, "ClassSheet");

    /**
     * Fields that were part of the legacy data model and have been removed from this class. The impacted packages
     * information ({@code mavenModules}, {@code affectedVersions}, {@code patchedVersions}) is now stored in dedicated
     * {@link ImpactedPackageClassMandatoryDocumentInitializer} objects, the {@code cve} field has been renamed to
     * {@link #FIELD_CVE_ID}, and {@code dataSpaceName} and {@code jiraTickets} are no longer used. These fields are
     * explicitly removed from the class on upgrade: {@link AbstractMandatoryClassInitializer} merges the class
     * definition without removing obsolete fields, and leaving them in the class would make XWiki recreate them
     * whenever an advisory object is saved (which notably breaks the data migration removing them).
     */
    private static final List<String> OBSOLETE_FIELDS =
        List.of("mavenModules", "affectedVersions", "patchedVersions", "cve", "dataSpaceName", "jiraTickets");

    @Inject
    @Named("class")
    protected SheetBinder classSheetBinder;

    /**
     * Default constructor.
     */
    public SecurityAdvisoryApplicationClassMandatoryDocumentInitializer()
    {
        super(CLASS_REFERENCE);
    }

    @Override
    public boolean updateDocument(XWikiDocument document)
    {
        // Let the default implementation add/update the fields defined in createClass. It merges the class with
        // clean=false, though, so it keeps any obsolete field still stored in the class. We remove those explicitly
        // below.
        boolean needUpdate = super.updateDocument(document);

        BaseClass xclass = document.getXClass();
        for (String obsoleteField : OBSOLETE_FIELDS) {
            if (xclass.getField(obsoleteField) != null) {
                xclass.removeField(obsoleteField);
                needUpdate = true;
            }
        }

        return needUpdate;
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        xclass.addTextField(FIELD_ADVISORY_LINK, FIELD_ADVISORY_LINK, 255);
        xclass.addTextField(FIELD_CVSS, FIELD_CVSS, 255);
        xclass.addTextField(FIELD_STATE, FIELD_STATE, 255);
        xclass.addTextField(FIELD_CVE_ID, FIELD_CVE_ID, 255);
        xclass.addNumberField(FIELD_CVSS_SCORE, FIELD_CVSS_SCORE, 10, NumberClass.TYPE_DOUBLE);
        xclass.addBooleanField(FIELD_COMPUTE_EMBARGO_DATE, FIELD_COMPUTE_EMBARGO_DATE, CHECKBOX_INPUT, null, true);
        xclass.addDateField(FIELD_EMBARGO_DATE, FIELD_EMBARGO_DATE, "dd/MM/yyyy");
        xclass.addStaticListField(FIELD_PRODUCT, FIELD_PRODUCT, 1, false, false, null,
            ListClass.DISPLAYTYPE_INPUT, null, null, ListClass.FREE_TEXT_ALLOWED, false);
        xclass.addStaticListField(FIELD_STATE, FIELD_STATE, 1, false,
            Stream.of(SecurityAdvisory.State.values())
                .map(state -> String.format("%s=%s", state.name(), state.name().toLowerCase()))
                .collect(Collectors.joining(ListClass.DEFAULT_SEPARATOR)),
            StaticListClass.DISPLAYTYPE_SELECT, ListClass.DEFAULT_SEPARATOR);
        xclass.addBooleanField(PREVENT_OVERRIDE, PREVENT_OVERRIDE, CHECKBOX_INPUT, null, false);

        String titleFieldName = "title1";
        ComputedFieldClass titleFieldClass = new ComputedFieldClass();
        titleFieldClass.setName(titleFieldName);
        titleFieldClass.setPrettyName("Title");
        titleFieldClass.setCustomDisplay("{{include reference=\"AppWithinMinutes.Title\"/}}");
        xclass.addField(titleFieldName, titleFieldClass);

        String descriptionFieldName = "description";
        ComputedFieldClass descriptionFieldClass = new ComputedFieldClass();
        descriptionFieldClass.setName(descriptionFieldName);
        descriptionFieldClass.setPrettyName("Description");
        descriptionFieldClass.setCustomDisplay("{{include reference=\"AppWithinMinutes.Content\"/}}");
        xclass.addField(descriptionFieldName, descriptionFieldClass);
    }

    @Override
    protected boolean updateDocumentSheet(XWikiDocument document)
    {
        this.documentSheetBinder.bind(document, CLASSSHEET_REFERENCE);
        return this.classSheetBinder.bind(document, SHEET_REFERENCE);
    }
}
