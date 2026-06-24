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
package org.xwiki.contrib.securityadvisory.internal.jobs;

import java.util.Date;
import java.util.List;

import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.contrib.securityadvisory.AdvisoryImporter;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoriesManager;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.VersionReleasedManager;

import com.xpn.xwiki.plugin.scheduler.AbstractJob;
import com.xpn.xwiki.web.Utils;

/**
 * Job in charge of importing latest advisories.
 *
 * @version $Id$
 * @since 2.0
 */
public class ImportAdvisoriesJob extends AbstractJob implements Job
{
    private static final Logger LOGGER = LoggerFactory.getLogger(ImportAdvisoriesJob.class);

    @Override
    protected void executeJob(JobExecutionContext jobContext)
    {
        SecurityAdvisoriesManager advisoriesManager = Utils.getComponent(SecurityAdvisoriesManager.class);
        VersionReleasedManager versionReleasedManager = Utils.getComponent(VersionReleasedManager.class);
        AdvisoryImporter importer = Utils.getComponent(AdvisoryImporter.class);
        SecurityAdvisoryConfiguration advisoryConfiguration = Utils.getComponent(SecurityAdvisoryConfiguration.class);
        Date lastImport = advisoryConfiguration.getLatestExecution();
        try {
            List<SecurityAdvisory> securityAdvisories = importer.importAdvisories(lastImport);
            for (SecurityAdvisory securityAdvisory : securityAdvisories) {
                advisoriesManager.writeAdvisory(securityAdvisory);
                if (versionReleasedManager.updateReleasedVersions(securityAdvisory)) {
                    advisoriesManager.writeAdvisoryImpactedPackagesReleaseInformation(securityAdvisory);
                }
            }
            advisoryConfiguration.updateLatestExecutionDate(new Date());
        } catch (SecurityAdvisoryException e) {
            LOGGER.error("Error while importing advisories", e);
        }
    }
}
