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

import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoriesManager;

import com.xpn.xwiki.plugin.scheduler.AbstractJob;
import com.xpn.xwiki.web.Utils;

/**
 * Job in charge of checking if an advisory is now disclosable.
 *
 * @version $Id$
 * @since 1.0
 */
public class ComputeDisclosableJob extends AbstractJob implements Job
{
    @Override
    protected void executeJob(JobExecutionContext jobContext) throws JobExecutionException
    {
        SecurityAdvisoriesManager advisoriesManager = Utils.getComponent(SecurityAdvisoriesManager.class);
        try {
            advisoriesManager.computeDisclosable();
        } catch (SecurityAdvisoryException e) {
            throw new JobExecutionException("Error when computing disclosable advisories", e);
        }
    }
}
