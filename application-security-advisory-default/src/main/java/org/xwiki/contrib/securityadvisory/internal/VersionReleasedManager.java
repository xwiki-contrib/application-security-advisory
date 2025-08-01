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

import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
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
     * Compute the embargo date for the given list of versions.
     * This method retrieves the date of the latest release among the given versions and adds the embargo duration
     * (defined in {@link SecurityAdvisoryConfiguration#getDefaultEmbargoDuration()}) to it. Note that this method
     * returns null if at least one of the given versions has not been released.
     *
     * @param advisory the advisory for which to compute the embargo date
     * @return a date after the embargo of latest release or {@code null} if one of the version is not released
     * @throws SecurityAdvisoryException in case of problem during the computation
     */
    public Date computeEmbargoDate(SecurityAdvisory advisory) throws SecurityAdvisoryException
    {
        Date result = null;
        List<Date> releaseDates = new ArrayList<>();
        String product = advisory.getProduct();
        for (String version : advisory.getPatchedVersions()) {
            if (this.isVersionReleased(product, version)) {
                releaseDates.add(this.getReleaseDate(product, version));
            } else {
                break;
            }
        }
        if (advisory.getPatchedVersions().size() == releaseDates.size()) {
            Date latestDate = getLatestDate(releaseDates);
            result = this.computeEmbargoDate(latestDate);
        }

        return result;
    }
}
