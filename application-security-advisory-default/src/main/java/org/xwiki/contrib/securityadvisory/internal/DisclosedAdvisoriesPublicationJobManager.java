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

import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.context.concurrent.ContextStoreManager;
import org.xwiki.job.Job;
import org.xwiki.job.JobException;
import org.xwiki.job.JobExecutor;
import org.xwiki.job.JobStatusStore;
import org.xwiki.job.event.status.JobStatus;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Starts the {@link DisclosedAdvisoriesPublicationJob} and gives access to its status.
 *
 * @version $Id$
 * @since 2.3.0
 */
@Component(roles = DisclosedAdvisoriesPublicationJobManager.class)
@Singleton
public class DisclosedAdvisoriesPublicationJobManager
{
    private static final List<String> JOB_ID = List.of("securityadvisory", "disclosedpublication");

    // The advisories are looked for in the current wiki, and publishing them checks the rights of the current user and
    // records them as creator of the published pages: both must be the ones of the user starting the job.
    private static final List<String> CONTEXT_ENTRIES = List.of("wiki", "user");

    @Inject
    private JobExecutor jobExecutor;

    @Inject
    private JobStatusStore jobStatusStore;

    @Inject
    private ContextStoreManager contextStoreManager;

    /**
     * Start a job publishing all the disclosed advisories that are not published yet, with the rights of the current
     * user. If such a job is already running, its status is returned instead.
     *
     * @return the status of the started job, or of the running one
     * @throws JobException in case of problem to start the job
     */
    public JobStatus startPublication() throws JobException
    {
        Job runningJob = this.jobExecutor.getJob(JOB_ID);
        if (runningJob != null) {
            return runningJob.getStatus();
        }
        try {
            return this.jobExecutor.execute(DisclosedAdvisoriesPublicationJob.JOBTYPE,
                new DisclosedAdvisoriesPublicationRequest(JOB_ID, this.contextStoreManager.save(CONTEXT_ENTRIES)))
                .getStatus();
        } catch (ComponentLookupException e) {
            throw new JobException("Failed to save the context of the publication of the disclosed advisories", e);
        }
    }

    /**
     * @return the status of the currently running or last executed publication job, or {@code null} if it has never
     *     been run
     */
    public JobStatus getPublicationStatus()
    {
        Job job = this.jobExecutor.getJob(JOB_ID);
        return (job != null) ? job.getStatus() : this.jobStatusStore.getJobStatus(JOB_ID);
    }
}
