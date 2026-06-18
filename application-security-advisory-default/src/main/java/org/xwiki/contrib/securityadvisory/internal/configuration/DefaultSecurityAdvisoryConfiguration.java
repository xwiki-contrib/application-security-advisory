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
package org.xwiki.contrib.securityadvisory.internal.configuration;

import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.commons.lang3.tuple.Pair;
import org.jodconverter.core.util.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceResolver;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceResolver;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import jakarta.inject.Provider;

/**
 * Default implementation of {@link SecurityAdvisoryConfiguration}.
 *
 * @version $Id$
 * @since 1.0
 */
@Component
@Singleton
public class DefaultSecurityAdvisoryConfiguration implements SecurityAdvisoryConfiguration
{
    private static final String CONFIGURATION_DOC_ACCESS_ERROR = "Cannot access configuration document";

    @Inject
    @Named("securityadvisory")
    private ConfigurationSource configurationSource;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    private EntityReferenceResolver<String> entityReferenceResolver;

    @Inject
    private UserReferenceResolver<String> userReferenceResolver;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private Logger logger;

    @Override
    public TemporalUnit getEmbargoDurationUnit()
    {
        String embargoDurationUnit =
            this.configurationSource.getProperty(
                SecurityAdvisoryConfigurationClassMandatoryDocumentInitializer.EMBARGO_DURATION_UNIT, "days");
        return ChronoUnit.valueOf(embargoDurationUnit.toUpperCase());
    }

    @Override
    public long getDefaultEmbargoDuration()
    {
        return this.configurationSource.getProperty(
            SecurityAdvisoryConfigurationClassMandatoryDocumentInitializer.DEFAULT_EMBARGO_DURATION, 90);
    }

    @Override
    public DocumentReference getSecurityGroup()
    {
        String securityGroup =
            this.configurationSource.getProperty(
                SecurityAdvisoryConfigurationClassMandatoryDocumentInitializer.SECURITY_GROUP, "XWiki.XWikiAdminGroup");
        return this.documentReferenceResolver.resolve(securityGroup);
    }

    @Override
    public SpaceReference getSecurityDataSpace()
    {
        String dataSpace =
            this.configurationSource.getProperty(
                SecurityAdvisoryConfigurationClassMandatoryDocumentInitializer.DATA_SPACE,
                "SecurityAdvisoryApplication.SecurityEntries");
        return new SpaceReference(this.entityReferenceResolver.resolve(dataSpace, EntityType.SPACE));
    }

    @Override
    public UserReference getAdvisoryImporterUser()
    {
        String importerUser =
            this.configurationSource.getProperty(
                SecurityAdvisoryConfigurationClassMandatoryDocumentInitializer.IMPORTER_USER, "XWiki.Admin");
        return this.userReferenceResolver.resolve(importerUser);
    }

    @Override
    public String getGithubImporterToken()
    {
        return this.configurationSource.getProperty(
            SecurityAdvisoryConfigurationClassMandatoryDocumentInitializer.GITHUB_TOKEN);
    }

    private XWikiDocument getConfigurationDoc() throws XWikiException
    {
        XWikiContext context = this.contextProvider.get();
        return context.getWiki().getDocument(SecurityAdvisoryConfigurationSource.DOC_REFERENCE, context);
    }

    private BaseObject getImporterExecutionDateObject(String importerName)
    {
        BaseObject result = null;
        try {
            XWikiDocument configurationDoc = getConfigurationDoc();
            for (BaseObject importerDateObject : configurationDoc.getXObjects(
                ImporterExecutionDateClassMandatoryDocumentInitializer.CLASS_REFERENCE)) {
                if (importerDateObject != null) {
                    String importObjectName = importerDateObject.getStringValue(
                        ImporterExecutionDateClassMandatoryDocumentInitializer.IMPORTER_NAME);
                    if (importerName.equals(importObjectName)) {
                        result = importerDateObject;
                        break;
                    }
                }
            }
        } catch (XWikiException e) {
            this.logger.error(CONFIGURATION_DOC_ACCESS_ERROR, e);
        }
        return result;
    }

    @Override
    public Date getLatestExecution(String importerName)
    {
        Date result = null;
        BaseObject importerExecutionDateObject = getImporterExecutionDateObject(importerName);
        if (importerExecutionDateObject != null) {
            result = importerExecutionDateObject
                .getDateValue(ImporterExecutionDateClassMandatoryDocumentInitializer.LAST_EXECUTION_DATE);
        }
        return result;
    }

    @Override
    public void updateLatestExecutionDate(Date executionDate, String importerName) throws SecurityAdvisoryException
    {
        BaseObject importerExecutionDateObject = getImporterExecutionDateObject(importerName);
        try {
            XWikiDocument configurationDoc = getConfigurationDoc().clone();
            XWikiContext context = contextProvider.get();
            if (importerExecutionDateObject == null) {
                importerExecutionDateObject =
                    configurationDoc.newXObject(ImporterExecutionDateClassMandatoryDocumentInitializer.CLASS_REFERENCE,
                        context);
                importerExecutionDateObject
                    .setStringValue(ImporterExecutionDateClassMandatoryDocumentInitializer.IMPORTER_NAME, importerName);
            }
            importerExecutionDateObject
                .setDateValue(ImporterExecutionDateClassMandatoryDocumentInitializer.LAST_EXECUTION_DATE,
                    executionDate);
            context.getWiki()
                .saveDocument(configurationDoc, "Update last execution date of " + importerName, true, context);
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException("Could not update last execution date of " + importerName, e);
        }
    }

    @Override
    public List<Pair<String, String>> getGithubRepositories()
    {
        List<Pair<String, String>> result = new ArrayList<>();
        try {
            XWikiDocument configurationDoc = getConfigurationDoc();
            for (BaseObject mappingObject : configurationDoc.getXObjects(
                RepositoryMappingClassMandatoryDocumentInitializer.CLASS_REFERENCE)) {
                if (mappingObject != null) {
                    String repositoryName = mappingObject.getStringValue(
                        RepositoryMappingClassMandatoryDocumentInitializer.REPOSITORY_NAME);
                    String projectName =
                        mappingObject.getStringValue(RepositoryMappingClassMandatoryDocumentInitializer.PROJECT_NAME);
                    if (StringUtils.isNotEmpty(repositoryName) && StringUtils.isNotEmpty(projectName)) {
                        result.add(Pair.of(repositoryName, projectName));
                    }
                }
            }
        } catch (XWikiException e) {
            this.logger.error(CONFIGURATION_DOC_ACCESS_ERROR, e);
        }
        return result;
    }
}
