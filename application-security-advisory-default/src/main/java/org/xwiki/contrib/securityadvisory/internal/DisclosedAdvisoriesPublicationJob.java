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
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.job.AbstractJob;
import org.xwiki.job.DefaultJobStatus;
import org.xwiki.job.GroupedJob;
import org.xwiki.job.JobGroupPath;
import org.xwiki.model.reference.DocumentReference;

import jakarta.inject.Inject;
import jakarta.inject.Named;

/**
 * Job publishing in the public data space all the advisories that are disclosed but not published yet: the ones
 * disclosed before the public data space existed, or imported as already published from an external source.
 *
 * @version $Id$
 * @since 2.3.0
 */
@Component
@Named(DisclosedAdvisoriesPublicationJob.JOBTYPE)
public class DisclosedAdvisoriesPublicationJob
    extends AbstractJob<DisclosedAdvisoriesPublicationRequest, DefaultJobStatus<DisclosedAdvisoriesPublicationRequest>>
    implements GroupedJob
{
    /**
     * The type of the job.
     */
    public static final String JOBTYPE = "securityadvisory.disclosedpublication";

    // Run the publications one after the other: two concurrent publications would try to publish the same advisories.
    private static final JobGroupPath GROUP_PATH =
        new JobGroupPath(List.of("securityadvisory", "disclosedpublication"));

    @Inject
    private DisclosedAdvisoryPublisher publisher;

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
        List<DocumentReference> advisories = this.publisher.getUnpublishedDisclosedAdvisories();
        this.progressManager.pushLevelProgress(advisories.size(), this);

        int published = 0;
        try {
            for (DocumentReference advisoryReference : advisories) {
                this.progressManager.startStep(this);
                try {
                    DocumentReference publicReference = this.publisher.publish(advisoryReference);
                    this.logger.info("Published advisory [{}] to [{}].", advisoryReference, publicReference);
                    published++;
                } catch (SecurityAdvisoryException e) {
                    // A failure to publish an advisory must not prevent the publication of the others.
                    this.logger.error("Failed to publish advisory [{}].", advisoryReference, e);
                }
                this.progressManager.endStep(this);
            }
        } finally {
            this.progressManager.popLevelProgress(this);
        }

        this.logger.info("Published [{}] advisories out of [{}] disclosed advisories not published yet.", published,
            advisories.size());
    }
}
