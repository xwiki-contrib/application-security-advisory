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

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.xwiki.job.Job;
import org.xwiki.job.JobExecutor;
import org.xwiki.job.JobStatusStore;
import org.xwiki.job.event.status.JobStatus;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link AssigneeResolutionJobManager}.
 *
 * @version $Id$
 */
@ComponentTest
class AssigneeResolutionJobManagerTest
{
    @InjectMockComponents
    private AssigneeResolutionJobManager jobManager;

    @MockComponent
    private JobExecutor jobExecutor;

    @MockComponent
    private JobStatusStore jobStatusStore;

    @Test
    void startResolutionAndGetStatus() throws Exception
    {
        assertNull(this.jobManager.getResolutionStatus());

        DocumentReference author = new DocumentReference("xwiki", "XWiki", "Admin");
        Job job = mock(Job.class);
        JobStatus jobStatus = mock(JobStatus.class);
        when(job.getStatus()).thenReturn(jobStatus);
        when(this.jobExecutor.execute(eq(AssigneeResolutionJob.JOBTYPE), any(AssigneeResolutionRequest.class)))
            .thenReturn(job);

        assertSame(jobStatus, this.jobManager.startResolution(author));

        ArgumentCaptor<AssigneeResolutionRequest> request = ArgumentCaptor.forClass(AssigneeResolutionRequest.class);
        verify(this.jobExecutor).execute(eq(AssigneeResolutionJob.JOBTYPE), request.capture());
        assertEquals(author, request.getValue().getAuthor());

        // The status of the running job is returned, or else the stored status of the last job.
        when(this.jobExecutor.getJob(request.getValue().getId())).thenReturn(job);
        assertSame(jobStatus, this.jobManager.getResolutionStatus());

        JobStatus storedStatus = mock(JobStatus.class);
        when(this.jobExecutor.getJob(request.getValue().getId())).thenReturn(null);
        when(this.jobStatusStore.getJobStatus(request.getValue().getId())).thenReturn(storedStatus);
        assertSame(storedStatus, this.jobManager.getResolutionStatus());
    }
}
