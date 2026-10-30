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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.AdvisoryImporter;
import org.xwiki.contrib.securityadvisory.ExternalUser;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoriesManager;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.VersionReleasedManager;
import org.xwiki.contrib.securityadvisory.internal.DisclosedAdvisoryPublisher;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryDataMigrator;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryMigrationJob;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryMigrationRequest;
import org.xwiki.contrib.securityadvisory.internal.assignee.AssigneeResolutionJobManager;
import org.xwiki.contrib.securityadvisory.internal.assignee.AssigneeResolver;
import org.xwiki.contrib.securityadvisory.internal.assignee.ExternalUserMappingStore;
import org.xwiki.job.Job;
import org.xwiki.job.JobException;
import org.xwiki.job.JobExecutor;
import org.xwiki.job.JobStatusStore;
import org.xwiki.job.event.status.JobStatus;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.AccessDeniedException;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceResolver;

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
@SuppressWarnings("checkstyle:ClassFanOutComplexity")
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

    @Inject
    private AssigneeResolver assigneeResolver;

    @Inject
    private AssigneeResolutionJobManager jobManager;

    @Inject
    private ExternalUserMappingStore externalUserMappingStore;

    @Inject
    @Named("document")
    private UserReferenceResolver<DocumentReference> userReferenceResolver;

    @Inject
    private DisclosedAdvisoryPublisher disclosedAdvisoryPublisher;

    @Inject
    private ContextualAuthorizationManager authorization;

    @Inject
    private SecurityAdvisoryConfiguration configuration;

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
     * Set the state of the advisory found thanks to the given reference. The current user needs edit right on the
     * advisory, and disclosing it also requires {@link #canDisclose(DocumentReference)}, since it publishes the
     * advisory in the public data space.
     *
     * @param advisoryReference the reference of the advisory.
     * @param state the new state to set.
     * @throws SecurityAdvisoryException if no advisory can be found, if the current user is not allowed to set this
     *     state, or in case of problem to set its state
     * @see SecurityAdvisoriesManager#setStatus(SecurityAdvisory, SecurityAdvisory.State)
     * @since 2.2.0
     */
    public void setStatus(DocumentReference advisoryReference, SecurityAdvisory.State state)
        throws SecurityAdvisoryException
    {
        if (!this.authorization.hasAccess(Right.EDIT, advisoryReference)
            || (state == SecurityAdvisory.State.DISCLOSED && !canDisclose(advisoryReference))) {
            throw new SecurityAdvisoryException(
                String.format("The current user is not allowed to set the status [%s] on the advisory [%s].", state,
                    advisoryReference));
        }
        Optional<SecurityAdvisory> securityAdvisoryOpt = this.securityAdvisoriesManager.loadAdvisory(advisoryReference);
        if (securityAdvisoryOpt.isPresent()) {
            this.securityAdvisoriesManager.setStatus(securityAdvisoryOpt.get(), state);
        } else {
            throw new SecurityAdvisoryException(String.format("Cannot find advisory with reference [%s]",
                 advisoryReference));
        }
    }

    /**
     * List the external users of the given advisory which prevent it from being assigned because they are not mapped
     * to an XWiki user.
     *
     * @param advisoryReference the reference of the advisory
     * @return the external users of the advisory without mapping, by order of priority, or an empty list if the
     *     advisory already has an assignee or if the current user cannot view it
     * @throws SecurityAdvisoryException in case of problem to load the advisory or to read the mapping
     * @since 2.2.2
     */
    public List<ExternalUser> getUnmappedExternalUsers(DocumentReference advisoryReference)
        throws SecurityAdvisoryException
    {
        List<ExternalUser> result = Collections.emptyList();
        if (this.authorization.hasAccess(Right.VIEW, advisoryReference)) {
            Optional<SecurityAdvisory> advisoryOpt = this.securityAdvisoriesManager.loadAdvisory(advisoryReference);
            if (advisoryOpt.isPresent()) {
                result = this.assigneeResolver.getUnmappedExternalUsers(advisoryOpt.get());
            }
        }
        return result;
    }

    /**
     * Only administrators can get this count, which is meant for the live data listing the external users.
     *
     * @param hint the hint of the external system the user belongs to (e.g. {@code github})
     * @param externalId the stable identifier of the user in the external system
     * @return the number of advisories without assignee the external user is involved in, or {@code 0} if the
     *     current user is not an administrator
     * @throws SecurityAdvisoryException in case of problem to query or load the advisories
     * @since 2.2.2
     */
    public int countUnassignedAdvisories(String hint, String externalId) throws SecurityAdvisoryException
    {
        int result = 0;
        if (this.authorization.hasAccess(Right.ADMIN, this.contextProvider.get().getWikiReference())) {
            result = this.assigneeResolver.countUnassignedAdvisories(new ExternalUser(hint, externalId, null));
        }
        return result;
    }

    /**
     * Map an external user to an XWiki user, replacing the existing mapping of the external user if any, and assign
     * the given advisory if it has no assignee yet. The other advisories without assignee are then assigned in the
     * background. Only administrators can create a mapping: it decides who is in charge of embargoed advisories.
     *
     * @param hint the hint of the external system the user belongs to (e.g. {@code github})
     * @param externalId the stable identifier of the user in the external system
     * @param login the login of the user in the external system
     * @param userReference the reference of the XWiki user to map the external user to
     * @param advisoryReference the reference of an advisory to assign right away, or {@code null}
     * @throws AccessDeniedException if the current user is not an administrator
     * @throws SecurityAdvisoryException in case of problem to save the mapping or the advisory
     * @since 2.2.2
     */
    public void linkExternalUser(String hint, String externalId, String login, DocumentReference userReference,
        DocumentReference advisoryReference) throws AccessDeniedException, SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        this.authorization.checkAccess(Right.ADMIN, context.getWikiReference());

        UserReference user = this.userReferenceResolver.resolve(userReference);
        this.externalUserMappingStore.setMapping(new ExternalUser(hint, externalId, login), user);

        if (advisoryReference != null) {
            this.assigneeResolver.resolveAssignee(advisoryReference,
                this.userReferenceResolver.resolve(context.getUserReference()));
        }
    }

    /**
     * Archive or unarchive an external user: an archived external user is known not to be mappable, and is not
     * proposed for mapping anymore. Only administrators can archive an external user.
     *
     * @param hint the hint of the external system the user belongs to (e.g. {@code github})
     * @param externalId the stable identifier of the user in the external system
     * @param login the login of the user in the external system
     * @param archived {@code true} to archive the external user, {@code false} to unarchive it
     * @throws AccessDeniedException if the current user is not an administrator
     * @throws SecurityAdvisoryException in case of problem to save the external user
     * @since 2.2.2
     */
    public void setExternalUserArchived(String hint, String externalId, String login, boolean archived)
        throws AccessDeniedException, SecurityAdvisoryException
    {
        this.authorization.checkAccess(Right.ADMIN, this.contextProvider.get().getWikiReference());
        this.externalUserMappingStore.setArchived(new ExternalUser(hint, externalId, login), archived);
    }

    /**
     * Start a job assigning all the advisories without assignee from the mapping of their external users. Only
     * administrators can start it.
     *
     * @return the status of the started job
     * @throws AccessDeniedException if the current user is not an administrator
     * @throws JobException in case of problem to start the job
     * @since 2.2.2
     */
    public JobStatus startAssigneeResolution() throws AccessDeniedException, JobException
    {
        XWikiContext context = this.contextProvider.get();
        this.authorization.checkAccess(Right.ADMIN, context.getWikiReference());
        return this.jobManager.startResolution(context.getUserReference());
    }

    /**
     * @return the status of the currently running or last executed assignee resolution job, or {@code null} if it has
     *     never been run
     * @since 2.2.2
     */
    public JobStatus getAssigneeResolutionStatus()
    {
        return this.jobManager.getResolutionStatus();
    }

    /**
     * Check if the current user can disclose the given advisory: it must be disclosable, and the user needs edit right
     * both on the advisory and on the public data space where it gets published.
     *
     * @param advisoryReference the reference of the advisory
     * @return {@code true} if the current user can disclose the advisory
     * @throws SecurityAdvisoryException in case of problem to load the advisory
     * @since 2.3.0
     */
    public boolean canDisclose(DocumentReference advisoryReference) throws SecurityAdvisoryException
    {
        Optional<SecurityAdvisory> securityAdvisoryOpt = this.securityAdvisoriesManager.loadAdvisory(advisoryReference);
        return securityAdvisoryOpt.isPresent()
            && securityAdvisoryOpt.get().getState() == SecurityAdvisory.State.DISCLOSABLE
            && this.disclosedAdvisoryPublisher.canPublish(advisoryReference);
    }

    /**
     * @return the space where disclosed advisories are published
     * @since 2.3.0
     */
    public SpaceReference getPublicDataSpace()
    {
        return this.configuration.getPublicDataSpace();
    }

    /**
     * @param advisoryReference the reference of an advisory located in the security data space
     * @return the reference of the page where the advisory is published once disclosed
     * @since 2.3.0
     */
    public DocumentReference getPublicReference(DocumentReference advisoryReference)
    {
        return this.disclosedAdvisoryPublisher.getPublicReference(advisoryReference);
    }

    /**
     * List the advisories that are disclosed but not published in the public data space yet, e.g. because they were
     * disclosed before the public data space existed. Only wiki administrators can list them.
     *
     * @return the references of the disclosed advisories to publish, or an empty list if the current user is not a
     *     wiki administrator
     * @throws SecurityAdvisoryException in case of problem to retrieve the advisories
     * @since 2.3.0
     */
    public List<DocumentReference> getUnpublishedDisclosedAdvisories() throws SecurityAdvisoryException
    {
        if (!this.authorization.hasAccess(Right.ADMIN)) {
            return List.of();
        }
        return this.disclosedAdvisoryPublisher.getUnpublishedDisclosedAdvisories();
    }

    /**
     * Publish in the public data space all the advisories returned by {@link #getUnpublishedDisclosedAdvisories()}.
     * Only wiki administrators can perform this operation. A failure to publish an advisory doesn't stop the
     * publication of the others.
     *
     * @return for each advisory to publish, {@code null} if it has been published, or the reason why it couldn't be
     * @throws SecurityAdvisoryException if the current user is not a wiki administrator, or in case of problem to
     *     retrieve the advisories
     * @since 2.3.0
     */
    public Map<DocumentReference, String> publishDisclosedAdvisories() throws SecurityAdvisoryException
    {
        if (!this.authorization.hasAccess(Right.ADMIN)) {
            throw new SecurityAdvisoryException("Only wiki administrators can publish the disclosed advisories.");
        }
        Map<DocumentReference, String> results = new LinkedHashMap<>();
        for (DocumentReference advisoryReference : this.disclosedAdvisoryPublisher
            .getUnpublishedDisclosedAdvisories()) {
            try {
                this.disclosedAdvisoryPublisher.publish(advisoryReference);
                results.put(advisoryReference, null);
            } catch (SecurityAdvisoryException e) {
                results.put(advisoryReference, e.getMessage());
            }
        }
        return results;
    }
}
