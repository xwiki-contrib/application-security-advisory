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
package org.xwiki.contrib.securityadvisory;

import java.time.temporal.TemporalUnit;
import java.util.Date;
import java.util.List;

import org.xwiki.component.annotation.Role;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.user.UserReference;

/**
 * Configuration API for the application.
 *
 * @version $Id$
 * @since 1.0
 */
@Role
public interface SecurityAdvisoryConfiguration
{
    /**
     * @return the duration unit to use for embargo date.
     */
    TemporalUnit getEmbargoDurationUnit();

    /**
     * @return the actual embargo date duration.
     */
    long getDefaultEmbargoDuration();

    /**
     * @return the reference of the security group to use for notifications targets
     */
    DocumentReference getSecurityGroup();

    /**
     * @return the space where advisories should be saved.
     * @since 2.0
     */
    SpaceReference getSecurityDataSpace();

    /**
     * @return the reference of the user to use for saving imported data.
     * @since 2.0
     */
    UserReference getAdvisoryImporterUser();

    /**
     * @return the Github token used for reading repositories to import data
     * @see #getGithubRepositories()
     * @since 2.0
     */
    String getGithubImporterToken();

    /**
     * List the Github repositories slug (e.g. xwiki/xwiki-platform, or xwiki-contrib/application-changerequest) that
     * needs to be used for importing advisories.
     *
     * @return the list of repositories from where to import data, mapped to their product name.
     * @since 2.0
     */
    List<String> getGithubRepositories();

    /**
     * Retrieve the date of the last execution of the advisory importer.
     *
     * @return the date of last execution or {@code null} in case it hasn't been executed.
     * @since 2.0
     */
    Date getLatestExecution();

    /**
     * Record the date of last execution of the given importer.
     * @param executionDate the last execution date of the importer
     * @throws SecurityAdvisoryException in case of problem to save the data
     * @since 2.0
     */
    void updateLatestExecutionDate(Date executionDate) throws SecurityAdvisoryException;
}
