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
package org.xwiki.contrib.securityadvisory.script;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.AdvisoryImporter;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoriesManager;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.VersionReleasedManager;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryDataMigrator;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryMigrationJob;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryMigrationRequest;
import org.xwiki.job.Job;
import org.xwiki.job.JobException;
import org.xwiki.job.JobExecutor;
import org.xwiki.job.JobStatusStore;
import org.xwiki.job.event.status.JobStatus;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.script.service.ScriptService;

import com.xpn.xwiki.XWikiContext;

/**
 * Script service for security advisories.
 *
 * @version $Id$
 * @since 1.0
 */
@Component
@Named("securityadvisory")
@Singleton
public class SecurityAdvisoryScriptService implements ScriptService
{
    private static final List<String> DEFAULT_ENTRIES_SPACE = Arrays.asList("SecurityAdvisoryApplication",
        "SecurityEntries");

    private static final List<String> DATA_MIGRATION_JOB_ID = Arrays.asList("securityadvisory", "datamigration");

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private SecurityAdvisoriesManager securityAdvisoriesManager;

    @Inject
    private VersionReleasedManager versionReleasedManager;

    @Inject
    private AdvisoryImporter advisoryImporter;

    @Inject
    private SecurityAdvisoryDataMigrator dataMigrator;

    @Inject
    private JobExecutor jobExecutor;

    @Inject
    private JobStatusStore jobStatusStore;

    /**
     * Create a new unique advisory reference.
     *
     * @return a new unique document reference for an advisory to be created.
     */
    public DocumentReference getNewAdvisoryReference()
    {
        return new DocumentReference(UUID.randomUUID().toString(),
            new SpaceReference(contextProvider.get().getWikiReference().getName(),
            DEFAULT_ENTRIES_SPACE));
    }

    /**
     * Import the advisory located at the given URL and write its information as a new security advisory entry.
     *
     * @param externalAdvisoryUrl the URL of the external advisory
     * @return the reference of the document where the advisory is saved
     * @throws SecurityAdvisoryException in case of problem to import or write the advisory
     * @since 2.0
     */
    public DocumentReference importAndSaveAdvisory(String externalAdvisoryUrl)
        throws SecurityAdvisoryException
    {
        SecurityAdvisory securityAdvisory = this.advisoryImporter.importAdvisory(externalAdvisoryUrl);
        this.securityAdvisoriesManager.writeAdvisory(securityAdvisory);
        return securityAdvisory.getHolderReference();
    }

    /**
     * Start an asynchronous job migrating all the existing security advisory documents from the legacy data model to
     * the new one. This moves the impacted packages information that was stored directly on the advisory object into
     * dedicated impacted package objects, and migrates the CVE identifier. If the migration job is already running, its
     * status is returned without starting a new one.
     *
     * @return the status of the migration job
     * @throws JobException in case of problem to start the job
     * @since 2.0
     */
    public JobStatus startDataMigration() throws JobException
    {
        Job runningJob = this.jobExecutor.getJob(DATA_MIGRATION_JOB_ID);
        if (runningJob != null) {
            return runningJob.getStatus();
        }
        return this.jobExecutor
            .execute(SecurityAdvisoryMigrationJob.JOBTYPE, new SecurityAdvisoryMigrationRequest(DATA_MIGRATION_JOB_ID))
            .getStatus();
    }

    /**
     * @return the status of the currently running or last executed data migration job, or {@code null} if the
     *     migration has never been run
     * @since 2.0
     */
    public JobStatus getDataMigrationStatus()
    {
        Job job = this.jobExecutor.getJob(DATA_MIGRATION_JOB_ID);
        if (job != null) {
            return job.getStatus();
        }
        return this.jobStatusStore.getJobStatus(DATA_MIGRATION_JOB_ID);
    }

    /**
     * @return the number of advisory documents that still hold legacy data and would be migrated
     * @throws SecurityAdvisoryException in case of problem to count the documents
     * @since 2.0
     */
    public long getDataMigrationCandidateCount() throws SecurityAdvisoryException
    {
        return this.dataMigrator.countDocumentsToMigrate();
    }

    /**
     * Compute and write release date information for the given advisory.
     * @param advisoryReference the advisory for which to compute information.
     * @return {@code true} if data have been updated, {@code false otherwise}.
     * @throws SecurityAdvisoryException in case of problem when loading information
     * @since 2.0
     */
    public boolean computeReleasedDateInformation(DocumentReference advisoryReference) throws SecurityAdvisoryException
    {
        boolean result = false;
        Optional<SecurityAdvisory> securityAdvisoryOpt = this.securityAdvisoriesManager.loadAdvisory(advisoryReference);
        if (securityAdvisoryOpt.isPresent()) {
            SecurityAdvisory securityAdvisory = securityAdvisoryOpt.get();
            boolean updated = this.versionReleasedManager.updateReleasedVersions(securityAdvisory);
            if (updated) {
                this.securityAdvisoriesManager.writeAdvisoryImpactedPackagesReleaseInformation(securityAdvisory);
                result = true;
            }
        }
        return result;
    }

    /**
     * Set the state of the advisory found thanks to the given reference.
     *
     * @param advisoryReference the reference of the advisory.
     * @param state the new state to set.
     * @throws SecurityAdvisoryException if no advisory can be found, or in case of problem to set its state
     * @see SecurityAdvisoriesManager#setStatus(SecurityAdvisory, SecurityAdvisory.State)
     * @since 2.2.0
     */
    public void setStatus(DocumentReference advisoryReference, SecurityAdvisory.State state)
        throws SecurityAdvisoryException
    {
        Optional<SecurityAdvisory> securityAdvisoryOpt = this.securityAdvisoriesManager.loadAdvisory(advisoryReference);
        if (securityAdvisoryOpt.isPresent()) {
            this.securityAdvisoriesManager.setStatus(securityAdvisoryOpt.get(), state);
        } else {
            throw new SecurityAdvisoryException(String.format("Cannot find advisory with reference [%s]",
                 advisoryReference));
        }
    }
}
