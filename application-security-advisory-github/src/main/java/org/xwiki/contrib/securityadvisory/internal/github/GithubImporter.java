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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.BasicHttpClientResponseHandler;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.ProtocolException;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.AdvisoryImporter;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Default implementation of advisory importer from Github.
 *
 * @version $Id$
 * @since 2.0
 */
@Component
@Singleton
public class GithubImporter implements AdvisoryImporter
{
    private static final String HEADER_ACCEPT = "application/vnd.github+json";
    private static final String GITHUB_REST_API_ENDPOINT =
        "https://api.github.com/repos/%s/security-advisories";
    private static final String GITHUB_REST_API_QUERIES = "?sort=updated&direction=desc&state=%s";
    private static final String GITHUB_API_TOKEN_HEADER = "Bearer %s";
    private static final String DRAFT_STATE = "draft";
    private static final String PUBLISHED_STATE = "published";
    private static final String LINK_HEADER = "link";
    private static final Pattern NEXT_PATTERN = Pattern.compile("(?<=<)([\\S]*)(?=>; rel=\"next\")");
    private static final Pattern ADVISORY_URL_PATTERN =
        Pattern.compile("^https://github\\.com/(?<repo>[\\S]+)/security/advisories/(?<ghsaId>[\\S]+)$");

    @Inject
    private GithubAdvisoryDeserializer deserializer;

    @Inject
    private SecurityAdvisoryConfiguration securityAdvisoryConfiguration;

    @Override
    public List<SecurityAdvisory> importAdvisories(boolean draft, Date limitDate) throws SecurityAdvisoryException
    {
        List<SecurityAdvisory> advisories = new ArrayList<>();
        List<Pair<String, String>> githubRepositories = this.securityAdvisoryConfiguration.getGithubRepositories();
        String githubImporterToken = this.securityAdvisoryConfiguration.getGithubImporterToken();
        String requestedState = draft ? DRAFT_STATE : PUBLISHED_STATE;
        for (Pair<String, String> githubRepository : githubRepositories) {
            String repoName = githubRepository.getLeft();
            String releaseProject = githubRepository.getRight();
            String firstQuery =
                String.format(GITHUB_REST_API_ENDPOINT + GITHUB_REST_API_QUERIES, repoName, requestedState);
            performQuery(firstQuery, releaseProject, limitDate, githubImporterToken, advisories, false);
        }
        return advisories;
    }

    @Override
    public SecurityAdvisory importAdvisory(String advisoryUrl, String releaseProject) throws SecurityAdvisoryException
    {
        Matcher matcher = ADVISORY_URL_PATTERN.matcher(advisoryUrl);
        if (matcher.matches()) {
            String githubImporterToken = this.securityAdvisoryConfiguration.getGithubImporterToken();
            String repo = matcher.group("repo");
            String ghsaId = matcher.group("ghsaId");
            String firstQuery = String.format(GITHUB_REST_API_ENDPOINT + "/%s", repo, ghsaId);
            List<SecurityAdvisory> result = new ArrayList<>();
            performQuery(firstQuery, releaseProject, null, githubImporterToken, result, true);
            if (!result.isEmpty()) {
                return result.get(0);
            } else {
                throw new SecurityAdvisoryException("No matching advisory found for " + advisoryUrl);
            }
        } else {
            throw new SecurityAdvisoryException(String.format("[%s] is not recognized as a Github advisory URL.",
                advisoryUrl));
        }
    }

    private void performQuery(String url, String releaseProject, Date limitDate, String token,
        List<SecurityAdvisory> advisories, boolean uniqueAdvisory)
        throws SecurityAdvisoryException
    {
        HttpGet getMethod = new HttpGet(url);
        injectHeaders(getMethod, token);
        try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
            String responseContent = httpclient.execute(getMethod, new BasicHttpClientResponseHandler());
            boolean limitDateReached =
                this.deserializer.processGithubResponse(releaseProject, limitDate, responseContent, uniqueAdvisory,
                    advisories);
            if (!limitDateReached && !uniqueAdvisory) {
                String nextPage = getNextPage(getMethod);
                if (nextPage != null) {
                    performQuery(nextPage, releaseProject, limitDate, token, advisories, uniqueAdvisory);
                }
            }
        } catch (IOException e) {
            throw new SecurityAdvisoryException(String.format("Error when trying to access [%s]", url), e);
        }
    }

    private void injectHeaders(HttpGet getMethod, String token)
    {
        getMethod.addHeader("Accept", HEADER_ACCEPT);
        getMethod.addHeader("Authorization", String.format(GITHUB_API_TOKEN_HEADER, token));
    }

    private String getNextPage(HttpGet getMethod) throws SecurityAdvisoryException
    {
        Header linkResponseHeader = null;
        try {
            linkResponseHeader = getMethod.getHeader(LINK_HEADER);
        } catch (ProtocolException e) {
            throw new SecurityAdvisoryException("Error while trying to read link header", e);
        }
        if (linkResponseHeader != null) {
            String headerValue = linkResponseHeader.getValue();
            Matcher matcher = NEXT_PATTERN.matcher(headerValue);
            if (matcher.find()) {
                return matcher.group(0);
            }
        }
        return null;
    }


}
