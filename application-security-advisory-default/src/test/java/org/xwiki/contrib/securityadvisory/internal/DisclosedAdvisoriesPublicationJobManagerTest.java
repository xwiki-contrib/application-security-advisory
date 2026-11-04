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

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.xwiki.context.concurrent.ContextStoreManager;
import org.xwiki.job.Job;
import org.xwiki.job.JobExecutor;
import org.xwiki.job.JobStatusStore;
import org.xwiki.job.event.status.JobStatus;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DisclosedAdvisoriesPublicationJobManager}.
 *
 * @version $Id$
 */
@ComponentTest
class DisclosedAdvisoriesPublicationJobManagerTest
{
    @InjectMockComponents
    private DisclosedAdvisoriesPublicationJobManager jobManager;

    @MockComponent
    private JobExecutor jobExecutor;

    @MockComponent
    private JobStatusStore jobStatusStore;

    @MockComponent
    private ContextStoreManager contextStoreManager;

    @Test
    void startPublicationAndGetStatus() throws Exception
    {
        assertNull(this.jobManager.getPublicationStatus());

        Map<String, Serializable> context = Map.of("wiki", "xwiki", "user", "xwiki:XWiki.Admin");
        when(this.contextStoreManager.save(List.of("wiki", "user"))).thenReturn(context);
        Job job = mock(Job.class);
        JobStatus jobStatus = mock(JobStatus.class);
        when(job.getStatus()).thenReturn(jobStatus);
        when(this.jobExecutor.execute(eq(DisclosedAdvisoriesPublicationJob.JOBTYPE),
            any(DisclosedAdvisoriesPublicationRequest.class))).thenReturn(job);

        assertSame(jobStatus, this.jobManager.startPublication());

        // The job runs in the wiki and with the rights of the user who started it.
        ArgumentCaptor<DisclosedAdvisoriesPublicationRequest> request =
            ArgumentCaptor.forClass(DisclosedAdvisoriesPublicationRequest.class);
        verify(this.jobExecutor).execute(eq(DisclosedAdvisoriesPublicationJob.JOBTYPE), request.capture());
        assertEquals(context, request.getValue().getContext());

        // While the job is running, its status is returned instead of starting another one.
        when(this.jobExecutor.getJob(request.getValue().getId())).thenReturn(job);
        assertSame(jobStatus, this.jobManager.startPublication());
        assertSame(jobStatus, this.jobManager.getPublicationStatus());
        verify(this.jobExecutor, times(1)).execute(any(), any());

        // Once finished, the stored status of the last job is returned.
        JobStatus storedStatus = mock(JobStatus.class);
        when(this.jobExecutor.getJob(request.getValue().getId())).thenReturn(null);
        when(this.jobStatusStore.getJobStatus(request.getValue().getId())).thenReturn(storedStatus);
        assertSame(storedStatus, this.jobManager.getPublicationStatus());
    }
}
