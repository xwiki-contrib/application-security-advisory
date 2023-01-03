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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.event.DisclosableComputedEvent;
import org.xwiki.contrib.securityadvisory.event.EmbargoDateComputedEvent;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.observation.ObservationManager;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Component in charge of manipulating {@link SecurityAdvisory}.
 *
 * @version $Id$
 * @since 1.0
 */
@Component(roles = SecurityAdvisoriesManager.class)
@Singleton
public class SecurityAdvisoriesManager
{
    private static final String SECURITY_ADVISORY_CLASS =
        "SecurityAdvisoryApplication.Code.SecurityAdvisoryApplicationClass";

    private static final String MISSING_OBJECT_EXCEPTION = "The holder document of the advisory does not contain "
        + "the proper xobject";
    private static final String READING_HOLDER_DOCUMENT_EXCEPTION = "Error when loading the holder document [%s]";

    private static final String FIELD_ADVISORY_LINK = "advisoryLink";
    private static final String FIELD_SEVERITY = "cvss";

    private static final String FIELD_PRODUCT = "product";

    /**
     * Field containing the state of the advisory.
     */
    private static final String FIELD_STATE = "status";

    /**
     * Field containing the list of affected versions.
     */
    private static final String FIELD_AFFECTED_VERSIONS = "affectedVersions";

    /**
     * Field containing the list of patched versions.
     */
    private static final String FIELD_PATCHED_VERSIONS = "patchedVersions";

    /**
     * Field containing the embargo date.
     */
    private static final String FIELD_EMBARGO_DATE = "embargoDate";

    /**
     * Field containing the flag to know if the embargo date should be computed or not.
     */
    private static final String FIELD_COMPUTE_EMBARGO_DATE = "computeEmbargo";

    /**
     * Field containing the issue tracker tickets.
     */
    private static final String FIELD_TICKETS = "jiraTickets";

    /**
     * Field containing the CVE identifier.
     */
    private static final String FIELD_CVE_ID = "cveId";

    /**
     * Field containing the list of impacted modules.
     */
    private static final String FIELD_IMPACTED_MODULES = "mavenModules";

    @Inject
    private QueryManager queryManager;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    private VersionReleasedManager versionReleasedManager;

    @Inject
    private ObservationManager observationManager;

    private List<SecurityAdvisory> getAdvisoriesWithStatus(SecurityAdvisory.State status, boolean computeEmbargoDate)
        throws SecurityAdvisoryException
    {
        String statement = String.format("from doc.object(%s) as objAdv where objAdv.%s = :status",
            SECURITY_ADVISORY_CLASS,
            FIELD_STATE);

        if (computeEmbargoDate) {
            statement += String.format(" and objAdv.%s = 1 and objAdv.%s is null",
                FIELD_COMPUTE_EMBARGO_DATE,
                FIELD_EMBARGO_DATE);
        }

        try {
            Query query = this.queryManager.createQuery(statement, Query.XWQL)
                .bindValue(FIELD_STATE, status.name());
            List<SecurityAdvisory> results = new ArrayList<>();
            for (Object reference : query.execute()) {
                DocumentReference documentReference = this.documentReferenceResolver.resolve(String.valueOf(reference));
                this.getAdvisoryFromDocument(documentReference).ifPresent(results::add);
            }
            return results;
        } catch (QueryException e) {
            throw new SecurityAdvisoryException("Error when retrieving advisories", e);
        }
    }

    private Optional<SecurityAdvisory> getAdvisoryFromDocument(DocumentReference documentReference)
        throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        Optional<SecurityAdvisory> result = Optional.empty();
        try {
            XWikiDocument document = context.getWiki().getDocument(documentReference, context);
            BaseObject xObject = document.getXObject(this.documentReferenceResolver.resolve(SECURITY_ADVISORY_CLASS));
            if (xObject != null) {
                SecurityAdvisory advisory = new SecurityAdvisory(documentReference);
                advisory.setAffectedVersions(xObject.getListValue(FIELD_AFFECTED_VERSIONS))
                    .setPatchedVersions(xObject.getListValue(FIELD_PATCHED_VERSIONS))
                    .setEmbargoDate(xObject.getDateValue(FIELD_EMBARGO_DATE))
                    .setComputeEmbargoDate(xObject.getIntValue(FIELD_COMPUTE_EMBARGO_DATE) == 1)
                    .setState(SecurityAdvisory.State.valueOf(xObject.getStringValue(FIELD_STATE).toUpperCase()))
                    .setCveId(xObject.getStringValue(FIELD_CVE_ID))
                    .setTickets(xObject.getListValue(FIELD_TICKETS))
                    .setImpactedModules(xObject.getListValue(FIELD_IMPACTED_MODULES))
                    .setAdvisoryLink(xObject.getStringValue(FIELD_ADVISORY_LINK))
                    .setProduct(xObject.getStringValue(FIELD_PRODUCT))
                    .setSeverity(xObject.getStringValue(FIELD_SEVERITY))
                    .setContent(document.getContent())
                    .setAuthor(document.getAuthors().getEffectiveMetadataAuthor());
                result = Optional.of(advisory);
            }
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(
                String.format("Error when loading the document [%s] to read the advisory", documentReference), e);
        }
        return result;
    }

    private void saveEmbargoDate(SecurityAdvisory securityAdvisory) throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        DocumentReference holderReference = securityAdvisory.getHolderReference();
        try {
            XWikiDocument document = context.getWiki().getDocument(holderReference, context);
            BaseObject xObject = document.getXObject(this.documentReferenceResolver.resolve(SECURITY_ADVISORY_CLASS));
            if (xObject != null) {
                xObject.setDateValue(FIELD_EMBARGO_DATE, securityAdvisory.getEmbargoDate());
                context.getWiki().saveDocument(document, "Set embargo date", context);
            } else {
                throw new SecurityAdvisoryException(MISSING_OBJECT_EXCEPTION);
            }
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(String.format(READING_HOLDER_DOCUMENT_EXCEPTION, holderReference), e);
        }
    }

    /**
     * Change the state of the given advisory to make it disclosable and save the new state.
     *
     * @param securityAdvisory the advisory that should now be disclosable.
     * @throws SecurityAdvisoryException in case of problem for saving.
     */
    private void saveDisclosable(SecurityAdvisory securityAdvisory) throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        DocumentReference holderReference = securityAdvisory.getHolderReference();
        try {
            XWikiDocument document = context.getWiki().getDocument(holderReference, context);
            BaseObject xObject = document.getXObject(this.documentReferenceResolver.resolve(SECURITY_ADVISORY_CLASS));
            if (xObject != null) {
                securityAdvisory.setState(SecurityAdvisory.State.DISCLOSABLE);
                xObject.setStringValue(FIELD_STATE, SecurityAdvisory.State.DISCLOSABLE.name());
                context.getWiki().saveDocument(document, "Set disclosable status", context);
            } else {
                throw new SecurityAdvisoryException(MISSING_OBJECT_EXCEPTION);
            }
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(String.format(READING_HOLDER_DOCUMENT_EXCEPTION, holderReference), e);
        }
    }

    /**
     * Retrieve all advisories that should be disclosable but are not yet: i.e. all advisories announced for which the
     * embargo date is over.
     * @return the list of disclosable advisories
     * @throws SecurityAdvisoryException in case of problem to retrieve the advisories
     */
    private List<SecurityAdvisory> getDisclosableAdvisories() throws SecurityAdvisoryException
    {
        return getAdvisoriesWithStatus(SecurityAdvisory.State.ANNOUNCED, false)
            .stream()
            .filter(SecurityAdvisory::isDisclosable)
            .collect(Collectors.toList());
    }

    /**
     * Retrieve advisories that should be now marked as disclosable and change their state before triggering an event.
     *
     * @throws SecurityAdvisoryException in case of problem for retrieving or saving the advisories
     */
    public void computeDisclosable() throws SecurityAdvisoryException
    {
        List<SecurityAdvisory> disclosableAdvisories = this.getDisclosableAdvisories();
        for (SecurityAdvisory disclosableAdvisory : disclosableAdvisories) {
            this.observationManager.notify(new DisclosableComputedEvent(), disclosableAdvisory);
            this.saveDisclosable(disclosableAdvisory);
        }
    }

    /**
     * Retrieve advisories for which the embargo date should be computed but is not defined yet, and compute their
     * embargo date if it's possible.
     *
     * @throws SecurityAdvisoryException in case of problem to compute the embargo date
     */
    public void computeEmbargoDates() throws SecurityAdvisoryException
    {
        List<SecurityAdvisory> advisories = this.getAdvisoriesWithStatus(SecurityAdvisory.State.ANNOUNCED, true);
        for (SecurityAdvisory advisory : advisories) {
            Date embargoDate = this.versionReleasedManager.computeEmbargoDate(advisory);
            if (embargoDate != null) {
                advisory.setEmbargoDate(embargoDate);
                this.saveEmbargoDate(advisory);
                this.observationManager.notify(new EmbargoDateComputedEvent(), advisory, embargoDate);
            }
        }
    }
}
