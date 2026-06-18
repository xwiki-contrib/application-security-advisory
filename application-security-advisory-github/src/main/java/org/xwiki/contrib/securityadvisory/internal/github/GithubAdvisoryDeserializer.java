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
package org.xwiki.contrib.securityadvisory.internal.github;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.ImpactedPackage;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoriesManager;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.github.Advisory;
import org.xwiki.contrib.securityadvisory.github.CVSSSeverity;
import org.xwiki.contrib.securityadvisory.github.PackageVulnerability;
import org.xwiki.contrib.securityadvisory.github.GithubState;
import org.xwiki.model.reference.DocumentReference;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.json.JsonMapper;

/**
 * Utility component for deserializing information from Github JSON.
 *
 * @version $Id$
 * @since 2.0
 */
@Component(roles = GithubAdvisoryDeserializer.class)
@Singleton
public class GithubAdvisoryDeserializer
{
    private static final String LOWER_INCLUSIVE = ">=";

    private static final String LOWER_EXCLUSIVE = ">";

    private static final String UPPER_INCLUSIVE = "<=";

    private static final String UPPER_EXCLUSIVE = "<";

    private static final String OPEN_UPPER_MAVEN_BOUND = ",)";

    private static final String OPEN_LOWER_MAVEN_BOUND = "(,";
    private static final String LIST_SEPARATOR = ",";

    @Inject
    private Logger logger;

    @Inject
    private SecurityAdvisoryConfiguration securityAdvisoryConfiguration;

    @Inject
    private SecurityAdvisoriesManager securityAdvisoriesManager;

    private ObjectMapper objectMapper;

    /**
     * Default constructor.
     */
    public GithubAdvisoryDeserializer()
    {
        this.objectMapper = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS, true)
            .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .build();
    }

    /**
     * Process the answer retrieved from Github API to parse it and populate the given list of advisories.
     * Note that only the advisories updated after the given limit date will be processed, and the method returns
     * {@code true} if that date is reached.
     *
     * @param releaseProject the project for which to build the advisories.
     * @param limitDate the limit date the advisories should be retrieved for.
     * @param response the response from Github API.
     * @param uniqueAdvisory {@code true} if the query is about a single advisory, {@code false} if it's about an
     * array of advisories
     * @param securityAdvisories the list of advisories to populate.
     * @return {@code true} if the limit date was reached while processing the advisories (i.e. some advisories were
     * ignored), {@code false} otherwise.
     * @throws SecurityAdvisoryException in case of problem for parsing the advisories.
     */
    public boolean processGithubResponse(String releaseProject, Date limitDate, String response, boolean uniqueAdvisory,
        List<SecurityAdvisory> securityAdvisories) throws SecurityAdvisoryException
    {
        boolean limitDateReached = false;
        try {
            if (uniqueAdvisory) {
                Advisory advisory = this.objectMapper.readValue(response, Advisory.class);
                SecurityAdvisory securityAdvisory = processGithubAdvisory(advisory, releaseProject);
                if (securityAdvisory != null) {
                    securityAdvisories.add(securityAdvisory);
                }
            } else {
                Advisory[] advisories = this.objectMapper.readValue(response, Advisory[].class);
                for (Advisory advisory : advisories) {
                    if (limitDate == null || advisory.updatedAt().after(limitDate)) {
                        SecurityAdvisory securityAdvisory = processGithubAdvisory(advisory, releaseProject);
                        if (securityAdvisory != null) {
                            securityAdvisories.add(securityAdvisory);
                        }
                    } else {
                        limitDateReached = true;
                        break;
                    }
                }
            }
        } catch (JsonProcessingException e) {
            throw new SecurityAdvisoryException("Error while processing JSON response", e);
        }
        return limitDateReached;
    }

    private SecurityAdvisory processGithubAdvisory(Advisory githubAdvisory, String releaseProject)
        throws SecurityAdvisoryException
    {
        GithubState state = githubAdvisory.state();
        if (StringUtils.isBlank(githubAdvisory.ghsaId())) {
            this.logger.warn("Missing ghsa ID on retrieved githubAdvisory, this will be skipped.");
            return null;
        } else if (state != GithubState.DRAFT && state != GithubState.PUBLISHED) {
            this.logger.info("Ignoring advisory [{}] as it's state is neither draft or published.",
                githubAdvisory.htmlUrl());
            return null;
        }
        DocumentReference advisoryReference = getReference(githubAdvisory);
        SecurityAdvisory advisory = new SecurityAdvisory(advisoryReference);
        boolean isPublished = state == GithubState.PUBLISHED;
        advisory
            .setAdvisoryLink(githubAdvisory.htmlUrl())
            .setAuthor(this.securityAdvisoryConfiguration.getAdvisoryImporterUser())
            .setTitle(githubAdvisory.summary())
            .setContent(githubAdvisory.description())
            .setProduct(releaseProject)
            .setState(isPublished ? SecurityAdvisory.State.DISCLOSED : SecurityAdvisory.State.DRAFT)
            .setComputeEmbargoDate(!isPublished);

        if (githubAdvisory.cvssSeverities() != null) {
            CVSSSeverity severity = (githubAdvisory.cvssSeverities().cvssV4().vectorString() != null)
                ? githubAdvisory.cvssSeverities().cvssV4() : githubAdvisory.cvssSeverities().cvssV3();
            advisory
                .setSeverity(severity.vectorString())
                .setCvssScore(severity.score());
        }
        if (githubAdvisory.vulnerabilities() != null) {
            handlePackages(githubAdvisory, advisory);
        }
        if (githubAdvisory.cveId() != null) {
            advisory.setCveId(githubAdvisory.cveId());
        }
        return advisory;
    }

    private void handlePackages(Advisory githubAdvisory, SecurityAdvisory advisory)
    {
        List<ImpactedPackage> impactedPackages = new ArrayList<>();
        for (PackageVulnerability vulnerability : githubAdvisory.vulnerabilities()) {
            impactedPackages.add(new ImpactedPackage(
                vulnerability.vulnerablePackage().name(),
                vulnerability.vulnerablePackage().ecosystem(),
                getRangeVersions(vulnerability),
                getPatchedVersions(vulnerability)
            ));
        }
        advisory.setVulnerablePackages(impactedPackages);
    }

    private DocumentReference getReference(Advisory githubAdvisory) throws SecurityAdvisoryException
    {
        Optional<DocumentReference> existingAdvisoryReferenceOpt =
            this.securityAdvisoriesManager.findExistingAdvisory(githubAdvisory.htmlUrl());
        return existingAdvisoryReferenceOpt.orElseGet(() ->
            new DocumentReference(githubAdvisory.ghsaId(), this.securityAdvisoryConfiguration.getSecurityDataSpace()));
    }

    private List<String> getPatchedVersions(PackageVulnerability vulnerability)
    {
        return List.of(StringUtils.split(vulnerability.patchedVersions(), LIST_SEPARATOR));
    }

    private List<String> getRangeVersions(PackageVulnerability vulnerability)
    {
        String range = vulnerability.vulnerableVersionRange();
        if (StringUtils.isBlank(range)) {
            return Collections.emptyList();
        }

        List<String> result = new ArrayList<>();
        String[] parts = StringUtils.split(range, ',');

        int i = 0;
        while (i < parts.length) {
            String current = parts[i].trim();
            if (isLowerBound(current) && i + 1 < parts.length && isUpperBound(parts[i + 1].trim())) {
                // Combine them
                result.add(convertToMaven(current, parts[i + 1].trim()));
                i += 2;
            } else {
                // Single bound
                result.add(convertSingleToMaven(current.trim()));
                i++;
            }
        }
        return result;
    }

    private boolean isLowerBound(String s)
    {
        return  s.startsWith(LOWER_INCLUSIVE) || s.startsWith(LOWER_EXCLUSIVE);
    }

    private boolean isUpperBound(String s)
    {
        return s.startsWith(UPPER_INCLUSIVE) || s.startsWith(UPPER_EXCLUSIVE);
    }

    private String convertSingleToMaven(String bound)
    {
        String result;
        if (bound.startsWith(LOWER_INCLUSIVE)) {
            result = '[' + bound.substring(2).trim() + OPEN_UPPER_MAVEN_BOUND;
        } else if (bound.startsWith(LOWER_EXCLUSIVE)) {
            result = '(' + bound.substring(1).trim() + OPEN_UPPER_MAVEN_BOUND;
        } else if (bound.startsWith(UPPER_INCLUSIVE)) {
            result = OPEN_LOWER_MAVEN_BOUND + bound.substring(2).trim() + ']';
        } else if (bound.startsWith(UPPER_EXCLUSIVE)) {
            result = OPEN_LOWER_MAVEN_BOUND + bound.substring(1).trim() + ')';
        } else if (bound.startsWith("=")) {
            result = '[' + bound.substring(1).trim() + ']';
        } else {
            // If no operator is present, keep it as is.
            result = bound;
        }
        return result;
    }

    private String convertToMaven(String lowerOrSingle, String upper)
    {
        String lowerPart = lowerOrSingle.trim();
        String upperPart = upper.trim();

        boolean isLowerInclusive = lowerPart.startsWith(LOWER_INCLUSIVE);
        char left = isLowerInclusive ? '[' : '(';
        String lowerVersion =
            isLowerInclusive ? lowerPart.substring(2).trim() : lowerPart.substring(1).trim();

        boolean isUpperInclusive = upperPart.startsWith(UPPER_INCLUSIVE);
        char right = isUpperInclusive ? ']' : ')';
        String upperVersion =
            isUpperInclusive ? upperPart.substring(2).trim() : upperPart.substring(1).trim();

        return left + lowerVersion + LIST_SEPARATOR + upperVersion + right;
    }
}
