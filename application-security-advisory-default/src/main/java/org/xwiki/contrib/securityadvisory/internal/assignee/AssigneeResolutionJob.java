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
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.job.AbstractJob;
import org.xwiki.job.DefaultJobStatus;
import org.xwiki.job.GroupedJob;
import org.xwiki.job.JobGroupPath;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceResolver;

import jakarta.inject.Inject;
import jakarta.inject.Named;

/**
 * Job setting the assignee of all the advisories without one, from the mapping of their external users. It's meant to
 * be run after a mapping is created, to apply it on the advisories that were imported before.
 *
 * @version $Id$
 * @since 2.3.0
 */
@Component
@Named(AssigneeResolutionJob.JOBTYPE)
public class AssigneeResolutionJob
    extends AbstractJob<AssigneeResolutionRequest, DefaultJobStatus<AssigneeResolutionRequest>>
    implements GroupedJob
{
    /**
     * The type of the job.
     */
    public static final String JOBTYPE = "securityadvisory.assigneeresolution";

    // Run the resolutions one after the other: a resolution started while another one is running must see the mapping
    // created just before, on all advisories, including the ones the running resolution already handled.
    private static final JobGroupPath GROUP_PATH = new JobGroupPath(List.of("securityadvisory", "assigneeresolution"));

    @Inject
    private AssigneeResolver assigneeResolver;

    @Inject
    @Named("document")
    private UserReferenceResolver<DocumentReference> userReferenceResolver;

    @Override
    public String getType()
    {
        return JOBTYPE;
    }

    @Override
    public JobGroupPath getGroupPath()
    {
        return GROUP_PATH;
    }

    @Override
    protected void runInternal() throws Exception
    {
        UserReference author = this.userReferenceResolver.resolve(getRequest().getAuthor());
        List<SecurityAdvisory> advisories = this.assigneeResolver.getUnassignedAdvisories();
        this.progressManager.pushLevelProgress(advisories.size(), this);

        int resolved = 0;
        try {
            for (SecurityAdvisory advisory : advisories) {
                this.progressManager.startStep(this);
                try {
                    if (this.assigneeResolver.resolveAssignee(advisory.getHolderReference(), author)) {
                        resolved++;
                    }
                } catch (Exception e) {
                    this.logger.error("Failed to set the assignee of advisory [{}].", advisory.getHolderReference(),
                        e);
                }
                this.progressManager.endStep(this);
            }
        } finally {
            this.progressManager.popLevelProgress(this);
        }

        this.logger.info("Assigned [{}] advisories out of [{}] advisories without assignee.", resolved,
            advisories.size());
    }
}
