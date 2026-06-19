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

import javax.inject.Inject;
import javax.inject.Named;

import org.xwiki.component.annotation.Component;
import org.xwiki.job.AbstractJob;
import org.xwiki.job.DefaultJobStatus;
import org.xwiki.model.reference.DocumentReference;

/**
 * Job migrating the existing security advisory documents from the legacy data model to the new one.
 *
 * @version $Id$
 * @since 2.0
 */
@Component
@Named(SecurityAdvisoryMigrationJob.JOBTYPE)
public class SecurityAdvisoryMigrationJob
    extends AbstractJob<SecurityAdvisoryMigrationRequest, DefaultJobStatus<SecurityAdvisoryMigrationRequest>>
{
    /**
     * The id of the job.
     */
    public static final String JOBTYPE = "securityadvisory.datamigration";

    @Inject
    private SecurityAdvisoryDataMigrator dataMigrator;

    @Override
    public String getType()
    {
        return JOBTYPE;
    }

    @Override
    protected void runInternal() throws Exception
    {
        List<DocumentReference> documentsToMigrate = this.dataMigrator.getDocumentsToMigrate();
        this.progressManager.pushLevelProgress(documentsToMigrate.size(), this);

        int migrated = 0;
        try {
            for (DocumentReference documentReference : documentsToMigrate) {
                this.progressManager.startStep(this);
                try {
                    if (this.dataMigrator.migrate(documentReference)) {
                        migrated++;
                    }
                } catch (Exception e) {
                    this.logger.error("Failed to migrate the security advisory document [{}].", documentReference, e);
                }
                this.progressManager.endStep(this);
            }
        } finally {
            this.progressManager.popLevelProgress(this);
        }

        this.logger.info("Migrated [{}] security advisory document(s) to the new data model out of [{}] candidate(s).",
            migrated, documentsToMigrate.size());
    }
}
