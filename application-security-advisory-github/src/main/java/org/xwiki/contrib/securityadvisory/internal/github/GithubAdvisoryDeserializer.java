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
import java.util.List;

import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.ImpactedPackage;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.github.Advisory;
import org.xwiki.contrib.securityadvisory.github.CVSSSeverity;
import org.xwiki.contrib.securityadvisory.github.PackageVulnerability;
import org.xwiki.model.reference.DocumentReference;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;

import jakarta.inject.Inject;

@Component(roles = GithubAdvisoryDeserializer.class)
@Singleton
public class GithubAdvisoryDeserializer
{
    @Inject
    private Logger logger;

    @Inject
    private SecurityAdvisoryConfiguration securityAdvisoryConfiguration;

    private ObjectMapper objectMapper;

    public GithubAdvisoryDeserializer()
    {
        this.objectMapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
    }

    public void processGithubResponse(String releaseProject, String response, List<SecurityAdvisory> securityAdvisories)
        throws SecurityAdvisoryException
    {
        try {
            Advisory[] advisories = this.objectMapper.readValue(response, Advisory[].class);
            for (Advisory advisory : advisories) {
                SecurityAdvisory securityAdvisory = processGithubAdvisory(advisory, releaseProject);
                if (securityAdvisory != null) {
                    securityAdvisories.add(securityAdvisory);
                }
            }
        } catch (JsonProcessingException e) {
            throw new SecurityAdvisoryException("Error while processing JSON response", e);
        }
    }

    private SecurityAdvisory processGithubAdvisory(Advisory githubAdvisory, String releaseProject)
    {
        if (StringUtils.isBlank(githubAdvisory.ghsaId())) {
            this.logger.warn("Missing ghsa ID on retrieved githubAdvisory, this will be skipped.");
            return null;
        }
        DocumentReference advisoryReference = new DocumentReference(githubAdvisory.ghsaId(),
            this.securityAdvisoryConfiguration.getSecurityDataSpace());
        SecurityAdvisory advisory = new SecurityAdvisory(advisoryReference);
        advisory
            .setAdvisoryLink(githubAdvisory.htmlUrl())
            .setAuthor(this.securityAdvisoryConfiguration.getGithubImporterUser())
            .setTitle(githubAdvisory.summary())
            .setContent(githubAdvisory.description())
            .setProduct(releaseProject);

        if (githubAdvisory.cvssSeverities() != null) {
            CVSSSeverity severity = (githubAdvisory.cvssSeverities().cvssV4().vectorString() != null) ?
                githubAdvisory.cvssSeverities().cvssV4() : githubAdvisory.cvssSeverities().cvssV3();
            advisory
                .setSeverity(severity.vectorString())
                .setCvssScore(severity.score());
        }
        if (githubAdvisory.vulnerabilities() != null) {
            List<ImpactedPackage> impactedPackages = new ArrayList<>();
            for (PackageVulnerability vulnerability : githubAdvisory.vulnerabilities()) {
                impactedPackages.add(new ImpactedPackage(
                    vulnerability.vulnerablePackage().name(),
                    getRangeVersions(vulnerability),
                    getPatchedVersions(vulnerability)
                ));
            }
            advisory.setVulnerablePackages(impactedPackages);
        }
        if (githubAdvisory.cveId() != null) {
            advisory.setCveId(githubAdvisory.cveId());
        }
        return advisory;
    }

    private List<String> getPatchedVersions(PackageVulnerability vulnerability)
    {
        return List.of(StringUtils.split(vulnerability.patchedVersions(), ","));
    }

    private List<String> getRangeVersions(PackageVulnerability vulnerability)
    {
        List<String> result = new ArrayList<>();
        for (String versionRange : StringUtils.split(vulnerability.vulnerableVersionRange(), ",")) {
            // FIXME: we should process the range
            result.add(versionRange);
        }
        return result;
    }
}
