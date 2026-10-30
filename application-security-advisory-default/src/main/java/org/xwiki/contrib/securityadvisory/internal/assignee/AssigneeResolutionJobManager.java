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
package org.xwiki.contrib.securityadvisory.internal.assignee;

import java.util.List;

import org.xwiki.component.annotation.Component;
import org.xwiki.job.Job;
import org.xwiki.job.JobException;
import org.xwiki.job.JobExecutor;
import org.xwiki.job.JobStatusStore;
import org.xwiki.job.event.status.JobStatus;
import org.xwiki.model.reference.DocumentReference;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Starts the {@link AssigneeResolutionJob} and gives access to its status.
 *
 * @version $Id$
 * @since 2.3.0
 */
@Component(roles = AssigneeResolutionJobManager.class)
@Singleton
public class AssigneeResolutionJobManager
{
    private static final List<String> JOB_ID = List.of("securityadvisory", "assigneeresolution");

    @Inject
    private JobExecutor jobExecutor;

    @Inject
    private JobStatusStore jobStatusStore;

    /**
     * Start a job assigning all the advisories without assignee from the mapping of their external users. The jobs
     * run one after the other, so a job started while another one is running sees the latest mapping.
     *
     * @param author the reference of the user to record as author of the changes made on the advisories
     * @return the status of the started job
     * @throws JobException in case of problem to start the job
     */
    public JobStatus startResolution(DocumentReference author) throws JobException
    {
        return this.jobExecutor.execute(AssigneeResolutionJob.JOBTYPE, new AssigneeResolutionRequest(JOB_ID, author))
            .getStatus();
    }

    /**
     * @return the status of the currently running or last executed assignee resolution job, or {@code null} if it has
     *     never been run
     */
    public JobStatus getResolutionStatus()
    {
        Job job = this.jobExecutor.getJob(JOB_ID);
        return (job != null) ? job.getStatus() : this.jobStatusStore.getJobStatus(JOB_ID);
    }
}
