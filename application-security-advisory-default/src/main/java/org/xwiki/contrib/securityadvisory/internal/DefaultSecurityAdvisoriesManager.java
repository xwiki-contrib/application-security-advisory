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

import org.apache.commons.lang3.StringUtils;
import org.metaeffekt.core.security.cvss.CvssVector;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.rendering.markdown.commonmark12.internal.CommonMark12SyntaxProvider;
import org.xwiki.contrib.securityadvisory.ImpactedPackage;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoriesManager;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.VersionReleasedManager;
import org.xwiki.contrib.securityadvisory.event.DisclosableComputedEvent;
import org.xwiki.contrib.securityadvisory.event.EmbargoDateComputedEvent;
import org.xwiki.model.document.DocumentAuthors;
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
@Component
@Singleton
@SuppressWarnings("checkstyle:ClassFanOutComplexity")
public class DefaultSecurityAdvisoriesManager implements SecurityAdvisoriesManager
{
    private static final String SECURITY_ADVISORY_CLASS =
        "SecurityAdvisoryApplication.Code.SecurityAdvisoryApplicationClass";

    private static final String MISSING_OBJECT_EXCEPTION = "The holder document of the advisory does not contain "
        + "the proper xobject";
    private static final String READING_HOLDER_DOCUMENT_EXCEPTION = "Error when loading the holder document [%s]";
    private static final String ADVISORY_ACCESS_EXCEPTION = "Error while trying to access document holding the "
        + "advisory [%s]";

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

    @Inject
    private Logger logger;

    private List<SecurityAdvisory> getAdvisoriesWithStatus(SecurityAdvisory.State status, boolean computeEmbargoDate)
        throws SecurityAdvisoryException
    {
        String statement = String.format("from doc.object(%s) as objAdv where objAdv.%s = :status",
            SECURITY_ADVISORY_CLASS,
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE);

        if (computeEmbargoDate) {
            statement += String.format(" and objAdv.%s = 1 and objAdv.%s is null",
                SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_COMPUTE_EMBARGO_DATE,
                SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_EMBARGO_DATE);
        }

        try {
            Query query = this.queryManager.createQuery(statement, Query.XWQL)
                .bindValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE, status.name());
            List<SecurityAdvisory> results = new ArrayList<>();
            for (Object reference : query.execute()) {
                DocumentReference documentReference = this.documentReferenceResolver.resolve(String.valueOf(reference));
                this.loadAdvisory(documentReference).ifPresent(results::add);
            }
            return results;
        } catch (QueryException e) {
            throw new SecurityAdvisoryException("Error when retrieving advisories", e);
        }
    }

    @Override
    public Optional<SecurityAdvisory> loadAdvisory(DocumentReference documentReference)
        throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        Optional<SecurityAdvisory> result = Optional.empty();
        try {
            XWikiDocument document = context.getWiki().getDocument(documentReference, context);
            BaseObject xObject = document.getXObject(this.documentReferenceResolver.resolve(SECURITY_ADVISORY_CLASS));
            if (xObject != null) {
                SecurityAdvisory advisory = new SecurityAdvisory(documentReference);
                advisory
                    .setEmbargoDate(
                        xObject.getDateValue(
                            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_EMBARGO_DATE))
                    .setComputeEmbargoDate(xObject.getIntValue(
                        SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_COMPUTE_EMBARGO_DATE) == 1)
                    .setState(SecurityAdvisory.State.valueOf(
                        xObject.getStringValue(
                            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE).toUpperCase()))
                    .setCveId(xObject.getStringValue(
                        SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVE_ID))
                    .setAdvisoryLink(
                        xObject.getStringValue(
                            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ADVISORY_LINK))
                    .setProduct(xObject.getStringValue(
                        SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_PRODUCT))
                    .setSeverity(xObject.getStringValue(
                        SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVSS))
                    .setContent(document.getContent())
                    .setAuthor(document.getAuthors().getEffectiveMetadataAuthor());
                setImpactedPackages(document, advisory);
                result = Optional.of(advisory);
            }
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(
                String.format(ADVISORY_ACCESS_EXCEPTION, documentReference), e);
        }
        return result;
    }

    private void setImpactedPackages(XWikiDocument document, SecurityAdvisory advisory)
    {
        List<BaseObject> impactedPackagesObjects =
            document.getXObjects(ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        List<ImpactedPackage> advisoryImpactedPackages = new ArrayList<>();

        for (BaseObject impactedPackagesObject : impactedPackagesObjects) {
            if (impactedPackagesObject != null) {
                advisoryImpactedPackages.add(readImpactedPackageObject(impactedPackagesObject));
            }
        }
        advisory.setVulnerablePackages(advisoryImpactedPackages);
    }

    private void saveEmbargoDate(SecurityAdvisory securityAdvisory) throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        DocumentReference holderReference = securityAdvisory.getHolderReference();
        try {
            XWikiDocument document = context.getWiki().getDocument(holderReference, context);
            BaseObject xObject = document.getXObject(this.documentReferenceResolver.resolve(SECURITY_ADVISORY_CLASS));
            if (xObject != null) {
                xObject.setDateValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_EMBARGO_DATE,
                    securityAdvisory.getEmbargoDate());
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
                xObject.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE,
                    SecurityAdvisory.State.DISCLOSABLE.name());
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

    @Override
    public void computeDisclosable() throws SecurityAdvisoryException
    {
        List<SecurityAdvisory> disclosableAdvisories = this.getDisclosableAdvisories();
        for (SecurityAdvisory disclosableAdvisory : disclosableAdvisories) {
            this.observationManager.notify(new DisclosableComputedEvent(), disclosableAdvisory);
            this.saveDisclosable(disclosableAdvisory);
        }
    }

    @Override
    public void computeEmbargoDates() throws SecurityAdvisoryException
    {
        List<SecurityAdvisory> advisories = this.getAdvisoriesWithStatus(SecurityAdvisory.State.ANNOUNCED, true);
        for (SecurityAdvisory advisory : advisories) {
            if (this.versionReleasedManager.updateReleasedVersions(advisory)) {
                this.writeAdvisoryImpactedPackagesReleaseInformation(advisory);
            }
            Optional<Date> embargoDate = this.versionReleasedManager.getEmbargoDate(advisory);
            if (embargoDate.isPresent()
                && (advisory.getEmbargoDate() == null
                || (!embargoDate.get().equals(advisory.getEmbargoDate())))) {
                advisory.setEmbargoDate(embargoDate.get());
                this.saveEmbargoDate(advisory);
                this.observationManager.notify(new EmbargoDateComputedEvent(), advisory, embargoDate);
            }
        }
    }

    @Override
    public void computeSeverityScore(SecurityAdvisory securityAdvisory) throws SecurityAdvisoryException
    {
        if (securityAdvisory.getCvssScore() == -1) {
            CvssVector cvssVector = CvssVector.parseVector(securityAdvisory.getSeverity());
            if (cvssVector != null) {
                securityAdvisory.setCvssScore(cvssVector.getBaseScore());
                XWikiContext context = this.contextProvider.get();
                DocumentReference holderReference = securityAdvisory.getHolderReference();
                try {
                    XWikiDocument document = context.getWiki().getDocument(holderReference, context);
                    BaseObject xObject =
                        document.getXObject(this.documentReferenceResolver.resolve(SECURITY_ADVISORY_CLASS));
                    if (xObject != null) {
                        xObject.setDoubleValue(
                            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVSS_SCORE,
                            securityAdvisory.getCvssScore());
                        context.getWiki().saveDocument(document, "Set CVSS Score", context);
                    } else {
                        throw new SecurityAdvisoryException(MISSING_OBJECT_EXCEPTION);
                    }
                } catch (XWikiException e) {
                    throw new SecurityAdvisoryException(
                        String.format(READING_HOLDER_DOCUMENT_EXCEPTION, holderReference), e);
                }
            }
        }
    }

    @Override
    public void writeAdvisory(SecurityAdvisory securityAdvisory) throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        try {
            XWikiDocument document = context.getWiki().getDocument(securityAdvisory.getHolderReference(), context);
            document = document.clone();
            BaseObject object = document.getXObject(
                SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE);
            boolean preventOverride = false;

            if (object == null) {
                object = document.newXObject(
                    SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE,
                    context);
            } else {
                preventOverride = object.getIntValue(
                    SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.PREVENT_OVERRIDE, 0) == 1;
            }
            if (preventOverride) {
                logger.info("Data from advisory [{}] won't be imported as the existing advisory prevents overriding.",
                    securityAdvisory.getAdvisoryLink());
                return;
            }

            document.setSyntax(CommonMark12SyntaxProvider.MARKDOWN_COMMON_1_2);
            document.setEnforceRequiredRights(true);
            document.setTitle(securityAdvisory.getTitle());
            DocumentAuthors authors = document.getAuthors();
            authors.setContentAuthor(securityAdvisory.getAuthor());
            authors.setEffectiveMetadataAuthor(securityAdvisory.getAuthor());
            authors.setOriginalMetadataAuthor(securityAdvisory.getAuthor());
            if (document.isNew()) {
                authors.setCreator(securityAdvisory.getAuthor());
            }
            document.setContent(securityAdvisory.getContent());
            setObjectValues(securityAdvisory, object);

            writeVulnerablePackages(document, securityAdvisory.getVulnerablePackages());
            context.getWiki().saveDocument(document, "Import data", context);
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(
                String.format(ADVISORY_ACCESS_EXCEPTION,
                    securityAdvisory.getHolderReference()), e);
        }
    }

    @Override
    public void writeAdvisoryImpactedPackagesReleaseInformation(SecurityAdvisory securityAdvisory)
        throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        XWikiDocument document = null;
        try {
            document = context.getWiki().getDocument(securityAdvisory.getHolderReference(), context);
            document = document.clone();
            writeVulnerablePackages(document, securityAdvisory.getVulnerablePackages());
            context.getWiki().saveDocument(document, "Update impacted package information", true, context);
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(
                String.format(ADVISORY_ACCESS_EXCEPTION, securityAdvisory.getHolderReference()), e);
        }
    }

    private static void setObjectValues(SecurityAdvisory securityAdvisory, BaseObject object)
    {
        object.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ADVISORY_LINK,
            securityAdvisory.getAdvisoryLink());
        object.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVSS,
            securityAdvisory.getSeverity());
        object.setDoubleValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVSS_SCORE,
            securityAdvisory.getCvssScore());
        object.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_PRODUCT,
            securityAdvisory.getProduct());
        object.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVE_ID,
            securityAdvisory.getCveId());
        object.setIntValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_COMPUTE_EMBARGO_DATE,
            securityAdvisory.isComputeEmbargoDate() ? 1 : 0);
        object.setIntValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.PREVENT_OVERRIDE, 0);

        if (StringUtils.isBlank(object.getStringValue(
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE)))
        {
            object.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE,
                securityAdvisory.getState().name());
        }
    }

    @Override
    public Optional<SecurityAdvisory> findExistingAdvisory(String externalAdvisoryURL) throws SecurityAdvisoryException
    {
        String statement = String.format("from doc.object(%s) as objAdv where objAdv.%s = :advisoryUrl",
            SECURITY_ADVISORY_CLASS,
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ADVISORY_LINK);

        Optional<SecurityAdvisory> result = Optional.empty();
        try {
            Query query = this.queryManager.createQuery(statement, Query.XWQL)
                .bindValue("advisoryUrl", externalAdvisoryURL)
                .setLimit(1);
            List<String> reference = query.execute();
            if (reference != null && reference.size() == 1) {
                result = loadAdvisory(this.documentReferenceResolver.resolve(String.valueOf(reference.get(0))));
            }
        } catch (QueryException e) {
            throw new SecurityAdvisoryException(
                String.format("Error when searching advisory with URL [%s]", externalAdvisoryURL), e);
        }
        return result;
    }

    private void writeVulnerablePackages(XWikiDocument document, List<ImpactedPackage> vulnerablePackages)
        throws XWikiException
    {
        List<BaseObject> existingImpactedPackagesObjects =
            document.getXObjects(ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        List<ImpactedPackage> mutatedVulnerablePackages = new ArrayList<>(vulnerablePackages);

        for (BaseObject existingImpactedPackagesObject : existingImpactedPackagesObjects) {
            if (existingImpactedPackagesObject != null) {
                mutatedVulnerablePackages.remove(readImpactedPackageObject(existingImpactedPackagesObject));
            }
        }
        if (!mutatedVulnerablePackages.isEmpty()) {
            // if at least one vulnerable packages needs to be written, then we rewrite all of them:
            // the reason is that we cannot easily identify if a package was previously partially written,
            // and the risk is to remains with those partial objects in the document. So it's easier to remove them all
            // and rewrite them all when one changed.

            document.removeXObjects(ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE);
            XWikiContext context = contextProvider.get();
            for (ImpactedPackage vulnerablePackage : vulnerablePackages) {
                BaseObject impactedPackageObject =
                    document.newXObject(ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE, context);
                impactedPackageObject.setStringValue(ImpactedPackageClassMandatoryDocumentInitializer.ECOSYSTEM,
                    vulnerablePackage.ecosystem());
                impactedPackageObject.setStringValue(ImpactedPackageClassMandatoryDocumentInitializer.PACKAGE_ID,
                    vulnerablePackage.packageName());
                impactedPackageObject.setStringListValue(
                    ImpactedPackageClassMandatoryDocumentInitializer.VULNERABLE_VERSION_RANGE,
                    vulnerablePackage.affectedVersionsRanges());
                impactedPackageObject.setStringListValue(
                    ImpactedPackageClassMandatoryDocumentInitializer.PATCHED_VERSIONS,
                    vulnerablePackage.patchedVersions());
                impactedPackageObject.setStringListValue(
                    ImpactedPackageClassMandatoryDocumentInitializer.RELEASED_VERSIONS,
                    vulnerablePackage.releasedVersions());
                if (vulnerablePackage.dateOfLatestRelease().isPresent()) {
                    impactedPackageObject.setDateValue(
                        ImpactedPackageClassMandatoryDocumentInitializer.LATEST_RELEASED_DATE,
                        vulnerablePackage.dateOfLatestRelease().get()
                    );
                }
            }
        }
    }

    private ImpactedPackage readImpactedPackageObject(BaseObject impactedPackagesObject)
    {
        String packageId =
            impactedPackagesObject.getStringValue(ImpactedPackageClassMandatoryDocumentInitializer.PACKAGE_ID);
        List<String> vulnerableRanges = impactedPackagesObject.getListValue(
            ImpactedPackageClassMandatoryDocumentInitializer.VULNERABLE_VERSION_RANGE);
        List<String> patchedVersions = impactedPackagesObject.getListValue(
            ImpactedPackageClassMandatoryDocumentInitializer.PATCHED_VERSIONS);
        List<String> releasedVersions = impactedPackagesObject.getListValue(
            ImpactedPackageClassMandatoryDocumentInitializer.RELEASED_VERSIONS);
        String ecosystem =
            impactedPackagesObject.getStringValue(ImpactedPackageClassMandatoryDocumentInitializer.ECOSYSTEM);
        Date latestReleasedDate =
            impactedPackagesObject.getDateValue(ImpactedPackageClassMandatoryDocumentInitializer.LATEST_RELEASED_DATE);
        Optional<Date> optionalDate = (latestReleasedDate != null) ? Optional.of(latestReleasedDate) : Optional.empty();
        return new ImpactedPackage(ecosystem, packageId, vulnerableRanges, patchedVersions, releasedVersions,
            optionalDate);
    }
}
