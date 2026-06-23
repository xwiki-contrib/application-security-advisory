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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.ImpactedPackage;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
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
@Component(roles = VersionReleasedManager.class)
@Singleton
public class VersionReleasedManager
{
    static final String RELEASE_NOTE_CLASS = "ReleaseNotes.Code.ReleaseNoteClass";

    private static final String XWIKI_PRODUCT = "XWiki";

    private static final String VERSION = "version";
    private static final String PRODUCT = "product";

    @Inject
    private QueryManager queryManager;

    @Inject
    private SecurityAdvisoryConfiguration configuration;

    @Inject
    private ExtensionRepositoryManager extensionRepositoryManager;

    /**
     * A computed embargo date based on the release date of the patched versions, or, if no release dates are
     * available, based on the current date. In that case, {@code updateExisting} will be {@code false} to indicate
     * that if the advisory already has an embargo date, it should not be updated with the computed one.
     *
     * @param embargoDate the computed embargo date
     * @param updateExisting whether to update the embargo date of the advisory if it already has one
     */
    public record ComputedEmbargoDate(Date embargoDate, boolean updateExisting) { }

    /**
     * Check if the given version is released.
     *
     * @param product the product for which to check if the version is released
     * @param version the version for which to check if it's released
     * @return {@code true} if the version is released according to the release notes.
     * @throws SecurityAdvisoryException in case of problem with the query to check if the version has been released
     */
    public boolean isVersionReleased(String product, String version) throws SecurityAdvisoryException
    {
        // TODO: introduce a cache
        String statement = String.format("from doc.object(%s) as objRelease where objRelease.released=1 and "
                + "objRelease.version=:version and objRelease.product=:product",
            RELEASE_NOTE_CLASS);
        try {
            Query query = this.queryManager
                .createQuery(statement, Query.XWQL)
                .bindValue(VERSION, version);
            if (StringUtils.startsWithIgnoreCase(product, XWIKI_PRODUCT)) {
                query = query.bindValue(PRODUCT, XWIKI_PRODUCT);
            } else {
                query = query.bindValue(PRODUCT, product);
            }
            return query.execute().size() > 0;
        } catch (QueryException e) {
            throw new SecurityAdvisoryException(
                String.format("Error when checking if [%s] has been released", version), e);
        }
    }

    /**
     * Retrieve the release date of the given version.
     *
     * @param product the product for which to retrieve the release date
     * @param version the version for which to retrieve the release date
     * @return the date of the release or {@code null} if the version cannot be found
     * @throws SecurityAdvisoryException in case of problem with the query
     */
    public Date getReleaseDate(String product, String version) throws SecurityAdvisoryException
    {
        String statement = String.format("select objRelease.date from Document doc, doc.object(%s) as objRelease "
                + "where objRelease.released=1 and objRelease.version=:version and objRelease.product=:product",
            RELEASE_NOTE_CLASS);
        try {
            Query query = this.queryManager
                .createQuery(statement, Query.XWQL)
                .bindValue(VERSION, version);
            if (StringUtils.startsWithIgnoreCase(product, XWIKI_PRODUCT)) {
                query = query.bindValue(PRODUCT, XWIKI_PRODUCT);
            } else {
                query = query.bindValue(PRODUCT, product);
            }
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

    /**
     * Compute the embargo date for the patched versions of the given advisory.
     * For XWiki core modules and products, this method retrieves the date of the latest release among the patched
     * versions (according to the release notes) and adds the embargo duration (defined in
     * {@link SecurityAdvisoryConfiguration#getDefaultEmbargoDuration()}) to it. For other extensions, the current date
     * is used as the release date when all patched versions are released, and the resulting
     * {@link ComputedEmbargoDate#updateExisting()} is {@code false}. This method returns {@code null} if no embargo
     * date could be computed, i.e. when one of the patched versions is not released yet.
     *
     * @param advisory the advisory for which to compute the embargo date
     * @return the computed embargo date or {@code null} if it could not be computed
     * @throws SecurityAdvisoryException in case of problem during the computation
     */
    public ComputedEmbargoDate computeEmbargoDate(SecurityAdvisory advisory) throws SecurityAdvisoryException
    {
        List<Date> releaseDates = new ArrayList<>();

        Map<String, List<String>> patchedVersionsByExtension = getPatchedVersionsByExtension(advisory);
        boolean updateExisting = true;

        for (Map.Entry<String, List<String>> entry : patchedVersionsByExtension.entrySet()) {
            String extensionId = entry.getKey();
            List<String> patchedVersions = entry.getValue();

            if (extensionId.equals(XWIKI_PRODUCT)) {
                // For XWiki product, we check the release notes for the product itself.
                if (!collectXWikiProductReleaseDates(patchedVersions, releaseDates)) {
                    // If any version is not released, we cannot compute an embargo date.
                    return null;
                }
            } else if (isAllExtensionVersionsReleased(extensionId, patchedVersions)) {
                // For other extensions, we check the extension repository if all versions are released.
                // We use the current date as the release date for the extension since we don't have a release date for
                // extensions.
                releaseDates.add(new Date());
                updateExisting = false;
            } else {
                // If not all patched versions of the extension are released, we cannot compute an embargo date.
                return null;
            }
        }

        if (releaseDates.isEmpty()) {
            // No release date could be determined (e.g. the patched versions of an extension are not all released),
            // we cannot compute an embargo date.
            return null;
        }

        Date latestDate = getLatestDate(releaseDates);
        return new ComputedEmbargoDate(this.computeEmbargoDate(latestDate), updateExisting);
    }

    /**
     * Collect the release dates of the given patched versions of the XWiki product from the release notes.
     *
     * @param patchedVersions the patched versions to check
     * @param releaseDates the list to which the found release dates are added
     * @return {@code true} if all the given versions are released, {@code false} as soon as one of them is not
     * @throws SecurityAdvisoryException in case of problem while querying the release notes
     */
    private boolean collectXWikiProductReleaseDates(List<String> patchedVersions, List<Date> releaseDates)
        throws SecurityAdvisoryException
    {
        for (String version : patchedVersions) {
            if (!isVersionReleased(XWIKI_PRODUCT, version)) {
                return false;
            }
            Date releaseDate = getReleaseDate(XWIKI_PRODUCT, version);
            if (releaseDate != null) {
                releaseDates.add(releaseDate);
            }
        }
        return true;
    }

    private static Map<String, List<String>> getPatchedVersionsByExtension(SecurityAdvisory advisory)
    {
        Map<String, List<String>> patchedVersionsByExtension = new HashMap<>();

        for (ImpactedPackage vulnerablePackage : advisory.getVulnerablePackages()) {
            String extensionId = vulnerablePackage.packageName();
            List<String> patchedVersions = vulnerablePackage.patchedVersions();
            if (!patchedVersions.isEmpty()) {
                String groupId = StringUtils.substringBefore(extensionId, ":");
                if (List.of("org.xwiki.commons", "org.xwiki.rendering", "org.xwiki.platform").contains(groupId)) {
                    // For XWiki core modules, we need to check the release note for the XWiki product
                    extensionId = XWIKI_PRODUCT;
                }
                patchedVersionsByExtension.computeIfAbsent(extensionId, k -> new ArrayList<>())
                    .addAll(patchedVersions);
            }
        }
        return patchedVersionsByExtension;
    }

    private boolean isAllExtensionVersionsReleased(String extensionId, List<String> patchedVersions)
    {
        return patchedVersions.stream()
            .allMatch(version -> this.extensionRepositoryManager.exists(new ExtensionId(extensionId, version)));
    }
}
