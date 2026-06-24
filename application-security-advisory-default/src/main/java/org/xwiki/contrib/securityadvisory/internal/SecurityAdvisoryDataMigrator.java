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
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoriesManager;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.VersionReleasedManager;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Migrate existing security advisory documents from the legacy data model to the new one.
 * <p>
 * In the legacy data model, the impacted packages information was stored as three parallel lists directly on the
 * {@code SecurityAdvisoryApplicationClass} object: {@code mavenModules} (the package coordinates), {@code
 * affectedVersions} and {@code patchedVersions}. The new data model stores this information in dedicated
 * {@code SecurityAdvisoryImpactedPackageClass} objects (one per package). The CVE identifier was also stored in a
 * {@code cve} field that is now named {@code cveId}.
 * <p>
 * This component creates one impacted package object per legacy Maven module (all sharing the legacy affected and
 * patched versions, with the {@code maven} ecosystem), copies the {@code cve} value into {@code cveId} when needed,
 * and removes the obsolete properties. The migration is idempotent: a document that has already been migrated is left
 * untouched.
 *
 * @version $Id$
 * @since 2.0
 */
@Component(roles = SecurityAdvisoryDataMigrator.class)
@Singleton
public class SecurityAdvisoryDataMigrator
{
    /**
     * Ecosystem used for the packages created from the legacy {@code mavenModules} field.
     */
    static final String MAVEN_ECOSYSTEM = "maven";

    /**
     * Legacy field holding the list of impacted Maven modules.
     */
    static final String LEGACY_FIELD_MAVEN_MODULES = "mavenModules";

    /**
     * Legacy field holding the list of affected version ranges.
     */
    static final String LEGACY_FIELD_AFFECTED_VERSIONS = "affectedVersions";

    /**
     * Legacy field holding the list of patched versions.
     */
    static final String LEGACY_FIELD_PATCHED_VERSIONS = "patchedVersions";

    /**
     * Legacy field holding the CVE identifier, now stored in {@code cveId}.
     */
    static final String LEGACY_FIELD_CVE = "cve";

    private static final String SECURITY_ADVISORY_CLASS =
        "SecurityAdvisoryApplication.Code.SecurityAdvisoryApplicationClass";

    private static final String MIGRATION_SAVE_COMMENT = "Migrate advisory to the new data model";

    private static final List<String> LEGACY_FIELDS = List.of(LEGACY_FIELD_MAVEN_MODULES,
        LEGACY_FIELD_AFFECTED_VERSIONS, LEGACY_FIELD_PATCHED_VERSIONS, LEGACY_FIELD_CVE);

    // A document needs migration as soon as its advisory object still holds one of the legacy properties. Those
    // properties have been removed from the XClass but are still stored, so we look them up by name in the generic
    // property table (BaseProperty maps to the xwikiproperties table, regardless of the property type).
    private static final String LEGACY_DATA_CONSTRAINT =
        " from BaseObject advisoryObj, BaseProperty legacyProp where advisoryObj.className = :className "
            + "and legacyProp.id.id = advisoryObj.id and legacyProp.id.name in (:legacyFields)";

    private static final String SELECT_DOCUMENTS_STATEMENT =
        "select distinct advisoryObj.name" + LEGACY_DATA_CONSTRAINT;

    private static final String COUNT_DOCUMENTS_STATEMENT =
        "select count(distinct advisoryObj.name)" + LEGACY_DATA_CONSTRAINT;

    @Inject
    private QueryManager queryManager;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    private VersionReleasedManager versionReleasedManager;

    @Inject
    private SecurityAdvisoriesManager advisoriesManager;

    @Inject
    private Logger logger;

    /**
     * Retrieve all the advisory documents that still hold legacy data and thus need to be migrated.
     *
     * @return the references of the documents to migrate
     * @throws SecurityAdvisoryException in case of problem to perform the query
     */
    public List<DocumentReference> getDocumentsToMigrate() throws SecurityAdvisoryException
    {
        try {
            List<DocumentReference> result = new ArrayList<>();
            for (Object name : createLegacyDataQuery(SELECT_DOCUMENTS_STATEMENT).execute()) {
                result.add(this.documentReferenceResolver.resolve(String.valueOf(name)));
            }
            return result;
        } catch (QueryException e) {
            throw new SecurityAdvisoryException("Error when retrieving advisories to migrate", e);
        }
    }

    /**
     * @return the number of advisory documents that still hold legacy data and thus need to be migrated
     * @throws SecurityAdvisoryException in case of problem to perform the query
     */
    public long countDocumentsToMigrate() throws SecurityAdvisoryException
    {
        try {
            List<Long> results = createLegacyDataQuery(COUNT_DOCUMENTS_STATEMENT).execute();
            return results.isEmpty() ? 0 : results.get(0);
        } catch (QueryException e) {
            throw new SecurityAdvisoryException("Error when counting advisories to migrate", e);
        }
    }

    private Query createLegacyDataQuery(String statement) throws QueryException
    {
        return this.queryManager.createQuery(statement, Query.HQL)
            .bindValue("className", SECURITY_ADVISORY_CLASS)
            .bindValue("legacyFields", LEGACY_FIELDS);
    }

    /**
     * Migrate a single advisory document and save it if it actually changed.
     *
     * @param documentReference the reference of the document to migrate
     * @return {@code true} if the document held legacy data and has been migrated and saved
     * @throws SecurityAdvisoryException in case of problem to load or save the document
     */
    public boolean migrate(DocumentReference documentReference) throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        try {
            XWikiDocument document = context.getWiki().getDocument(documentReference, context).clone();
            if (migrateDocument(document)) {
                context.getWiki().saveDocument(document, MIGRATION_SAVE_COMMENT, context);
                computeReleasedVersionInformation(documentReference);
                this.logger.info("Migrated security advisory [{}] to the new data model.", documentReference);
                return true;
            }
            return false;
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(
                String.format("Error while migrating the advisory document [%s]", documentReference), e);
        }
    }

    private void computeReleasedVersionInformation(DocumentReference documentReference) throws SecurityAdvisoryException
    {
        Optional<SecurityAdvisory> securityAdvisoryOpt = this.advisoriesManager.loadAdvisory(documentReference);
        if (securityAdvisoryOpt.isPresent()) {
            SecurityAdvisory securityAdvisory = securityAdvisoryOpt.get();
            boolean updated = this.versionReleasedManager.updateReleasedVersions(securityAdvisory);
            if (updated) {
                advisoriesManager.writeAdvisoryImpactedPackagesReleaseInformation(securityAdvisory);
            }
        }
    }

    /**
     * Perform the in-memory migration of the given document.
     *
     * @param document the document to migrate
     * @return {@code true} if the document has been modified
     */
    boolean migrateDocument(XWikiDocument document) throws XWikiException
    {
        BaseObject advisoryObject =
            document.getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        if (advisoryObject == null) {
            return false;
        }

        boolean changed = migrateImpactedPackages(document, advisoryObject);
        changed |= migrateCveId(advisoryObject);

        // Drop the obsolete properties now that their data has been moved to the new model.
        changed |= removeField(advisoryObject, LEGACY_FIELD_MAVEN_MODULES);
        changed |= removeField(advisoryObject, LEGACY_FIELD_AFFECTED_VERSIONS);
        changed |= removeField(advisoryObject, LEGACY_FIELD_PATCHED_VERSIONS);
        changed |= removeField(advisoryObject, LEGACY_FIELD_CVE);

        return changed;
    }

    private boolean migrateImpactedPackages(XWikiDocument document, BaseObject advisoryObject) throws XWikiException
    {
        // Only create impacted package objects if there is none yet, to keep the migration idempotent and to avoid
        // overriding data that would have been created with the new model.
        if (hasImpactedPackages(document)) {
            return false;
        }

        List<String> modules = advisoryObject.getListValue(LEGACY_FIELD_MAVEN_MODULES);
        List<String> affectedVersions = advisoryObject.getListValue(LEGACY_FIELD_AFFECTED_VERSIONS);
        List<String> patchedVersions = advisoryObject.getListValue(LEGACY_FIELD_PATCHED_VERSIONS);

        if (modules.isEmpty() && affectedVersions.isEmpty() && patchedVersions.isEmpty()) {
            return false;
        }

        XWikiContext context = this.contextProvider.get();
        if (modules.isEmpty()) {
            // No module was defined but there are versions: keep them in a single package without identifier.
            createImpactedPackage(document, context, null, affectedVersions, patchedVersions);
        } else {
            for (String module : modules) {
                createImpactedPackage(document, context, module, affectedVersions, patchedVersions);
            }
        }
        return true;
    }

    private void createImpactedPackage(XWikiDocument document, XWikiContext context, String module,
        List<String> affectedVersions, List<String> patchedVersions) throws XWikiException
    {
        BaseObject impactedPackageObject =
            document.newXObject(ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE, context);
        impactedPackageObject.setStringValue(ImpactedPackageClassMandatoryDocumentInitializer.ECOSYSTEM,
            MAVEN_ECOSYSTEM);
        if (module != null) {
            impactedPackageObject.setStringValue(ImpactedPackageClassMandatoryDocumentInitializer.PACKAGE_ID, module);
        }
        impactedPackageObject.setStringListValue(
            ImpactedPackageClassMandatoryDocumentInitializer.VULNERABLE_VERSION_RANGE, affectedVersions);
        impactedPackageObject.setStringListValue(
            ImpactedPackageClassMandatoryDocumentInitializer.PATCHED_VERSIONS, patchedVersions);
    }

    private boolean migrateCveId(BaseObject advisoryObject)
    {
        String legacyCve = advisoryObject.getStringValue(LEGACY_FIELD_CVE);
        String cveId =
            advisoryObject.getStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVE_ID);
        if (StringUtils.isNotBlank(legacyCve) && StringUtils.isBlank(cveId)) {
            advisoryObject.setStringValue(
                SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVE_ID, legacyCve);
            return true;
        }
        return false;
    }

    private boolean hasImpactedPackages(XWikiDocument document)
    {
        return document.getXObjects(ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE).stream()
            .anyMatch(Objects::nonNull);
    }

    private boolean removeField(BaseObject object, String fieldName)
    {
        if (object.safeget(fieldName) != null) {
            object.removeField(fieldName);
            return true;
        }
        return false;
    }
}
