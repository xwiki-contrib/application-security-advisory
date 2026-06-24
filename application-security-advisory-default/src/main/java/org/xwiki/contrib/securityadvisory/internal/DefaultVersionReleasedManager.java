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

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.ImpactedPackage;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.VersionReleasedManager;
import org.xwiki.extension.ExtensionId;
import org.xwiki.extension.repository.ExtensionRepositoryManager;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;

/**
 * Dedicated component to manipulate the released version as defined by the release note class.
 *
 * @version $Id$
 * @since 1.0
 */
@Component
@Singleton
public class DefaultVersionReleasedManager implements VersionReleasedManager
{
    static final String RELEASE_NOTE_CLASS = "ReleaseNotes.Code.ReleaseNoteClass";

    private static final String XWIKI_PRODUCT = "XWiki";

    private static final String VERSION = "version";
    private static final String PRODUCT = "product";

    private static final List<String> XWIKI_CORE_MODULES = List.of(
        "org.xwiki.commons",
        "org.xwiki.rendering",
        "org.xwiki.platform"
    );
    private static final String MAVEN_ECOSYSTEM = "maven";

    @Inject
    private QueryManager queryManager;

    @Inject
    private SecurityAdvisoryConfiguration configuration;

    @Inject
    private ExtensionRepositoryManager extensionRepositoryManager;

    @Inject
    private Logger logger;

    @Override
    public boolean updateReleasedVersions(SecurityAdvisory advisory) throws SecurityAdvisoryException
    {
        boolean updated = false;
        List<ImpactedPackage> newImpactedPackagesList = new ArrayList<>();
        for (ImpactedPackage impactedPackage : advisory.getVulnerablePackages()) {
            ArrayList<String> mutablePatchedVersions = new ArrayList<>(impactedPackage.patchedVersions());
            mutablePatchedVersions.removeAll(impactedPackage.releasedVersions());
            if (!mutablePatchedVersions.isEmpty()) {
                Date latestDate = null;
                List<String> releasedVersionsToAdd = new ArrayList<>();
                for (String patchedVersion : mutablePatchedVersions) {
                    Optional<Date> optionalDate =
                        computeReleased(advisory.getProduct(), impactedPackage, patchedVersion, releasedVersionsToAdd);
                    if (optionalDate.isPresent() && (latestDate == null || latestDate.before(optionalDate.get()))) {
                        latestDate = optionalDate.get();
                    }
                }
                if (!releasedVersionsToAdd.isEmpty()) {
                    updated = true;
                    releasedVersionsToAdd.addAll(impactedPackage.releasedVersions());
                    newImpactedPackagesList.add(new ImpactedPackage(
                        impactedPackage.ecosystem(),
                        impactedPackage.packageName(),
                        impactedPackage.affectedVersionsRanges(),
                        impactedPackage.patchedVersions(),
                        releasedVersionsToAdd,
                        Optional.of(latestDate)
                    ));
                } else {
                    newImpactedPackagesList.add(impactedPackage);
                }
            } else {
                newImpactedPackagesList.add(impactedPackage);
            }
        }
        if (updated) {
            advisory.setVulnerablePackages(newImpactedPackagesList);
        }
        return updated;
    }

    private Optional<Date> computeReleased(String productName, ImpactedPackage impactedPackage, String version,
        List<String> releasedVersionsToAdd)
        throws SecurityAdvisoryException
    {
        Optional<Date> result = Optional.empty();
        if (!Strings.CI.equals(impactedPackage.ecosystem(), MAVEN_ECOSYSTEM)) {
            this.logger.error("Impossible to test if [{}] has been released: [{}] ecosystem is not supported.",
                    impactedPackage.packageName(), impactedPackage.ecosystem());
            return result;
        }

        String groupId = StringUtils.substringBefore(impactedPackage.packageName(), ":");
        boolean isXS = XWIKI_CORE_MODULES.contains(groupId);
        Date obtainedDate;
        if (isXS) {
            obtainedDate = getReleaseDateFromReleaseNotes(XWIKI_PRODUCT, version);
        } else {
            obtainedDate = getReleaseDateFromReleaseNotes(productName, version);
            if (obtainedDate == null
                && this.extensionRepositoryManager.exists(new ExtensionId(impactedPackage.packageName(), version))) {
                obtainedDate = new Date();
            }
        }
        if (obtainedDate != null) {
            releasedVersionsToAdd.add(version);
            if (impactedPackage.dateOfLatestRelease().isEmpty()
                || obtainedDate.after(impactedPackage.dateOfLatestRelease().get())) {
                result = Optional.of(obtainedDate);
            } else {
                result = impactedPackage.dateOfLatestRelease();
            }
        }
        return result;
    }

    /**
     * Retrieve the release date of the given version.
     *
     * @param product the product for which to retrieve the release date
     * @param version the version for which to retrieve the release date
     * @return the date of the release or {@code null} if the version cannot be found
     * @throws SecurityAdvisoryException in case of problem with the query
     */
    private Date getReleaseDateFromReleaseNotes(String product, String version) throws SecurityAdvisoryException
    {
        String statement = String.format("select objRelease.date from Document doc, doc.object(%s) as objRelease "
                + "where objRelease.released=1 and objRelease.version=:version and objRelease.product=:product",
            RELEASE_NOTE_CLASS);
        try {
            Query query = this.queryManager
                .createQuery(statement, Query.XWQL)
                .bindValue(VERSION, version)
                .bindValue(PRODUCT, product);

            List<Object> result = query.execute();
            if (!result.isEmpty()) {
                return (Date) result.get(0);
            } else {
                return null;
            }
        } catch (QueryException e) {
            throw new SecurityAdvisoryException(
                String.format("Error when checking when [%s] has been released", version), e);
        }
    }

    @Override
    public Optional<Date> getEmbargoDate(SecurityAdvisory advisory)
    {
        List<Date> latestReleasedVersions = new ArrayList<>();
        boolean areAllReleased = !advisory.getVulnerablePackages().isEmpty();
        for (ImpactedPackage vulnerablePackage : advisory.getVulnerablePackages()) {
            if (!vulnerablePackage.patchedVersions().isEmpty()) {
                List<String> patchedVersions = new ArrayList<>(vulnerablePackage.patchedVersions());
                patchedVersions.removeAll(vulnerablePackage.releasedVersions());
                areAllReleased &= patchedVersions.isEmpty();
                vulnerablePackage.dateOfLatestRelease().ifPresent(latestReleasedVersions::add);
            }
        }
        Optional<Date> result = Optional.empty();
        if (areAllReleased && !latestReleasedVersions.isEmpty()) {
            Date latestReleasedDate = getLatestDate(latestReleasedVersions);
            Date embargoDate = computeEmbargoDate(latestReleasedDate);
            result = Optional.of(embargoDate);
        }

        return result;
    }

    private Date getLatestDate(List<Date> dateList)
    {
        Collections.sort(dateList);
        return dateList.get(dateList.size() - 1);
    }

    protected Date computeEmbargoDate(Date latestDate)
    {
        LocalDateTime localDateTime = LocalDateTime.ofInstant(latestDate.toInstant(), ZoneOffset.UTC)
            .plus(this.configuration.getDefaultEmbargoDuration(), this.configuration.getEmbargoDurationUnit());

        return Date.from(localDateTime.toInstant(ZoneOffset.UTC));
    }
}
