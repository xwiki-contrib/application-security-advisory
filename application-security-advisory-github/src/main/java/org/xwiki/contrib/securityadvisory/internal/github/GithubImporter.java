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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.AdvisoryImporter;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;

@Component
@Singleton
public class GithubImporter implements AdvisoryImporter
{
    private static final String HEADER_ACCEPT = "application/vnd.github+json";
    private static final String GITHUB_API_ENDPOINT = "https://api.github.com/repos/%s/security-advisories?state=%s";
    private static final String GITHUB_API_TOKEN_HEADER = "Bearer %s";
    private static final String DRAFT_STATE = "draft";
    private static final String PUBLISHED_STATE = "published";
    private static final String LINK_HEADER = "link";
    private static final Pattern NEXT_PATTERN = Pattern.compile("(?<=<)([\\S]*)(?=>; rel=\"next\")");

    @Inject
    private GithubAdvisoryDeserializer deserializer;

    @Inject
    private SecurityAdvisoryConfiguration securityAdvisoryConfiguration;

    @Inject
    private Logger logger;

    private HttpClient httpClient;

    public GithubImporter()
    {
        this(new HttpClient());
    }

    public GithubImporter(HttpClient httpClient)
    {
        this.httpClient = httpClient;

    }


    @Override
    public List<SecurityAdvisory> importAdvisories(boolean draft) throws SecurityAdvisoryException
    {
        List<SecurityAdvisory> advisories = new ArrayList<>();
        List<Pair<String, String>> githubRepositories = this.securityAdvisoryConfiguration.getGithubRepositories();
        String githubImporterToken = this.securityAdvisoryConfiguration.getGithubImporterToken();
        String requestedState = draft ? DRAFT_STATE : PUBLISHED_STATE;
        for (Pair<String, String> githubRepository : githubRepositories) {
            String repoName = githubRepository.getLeft();
            String releaseProject = githubRepository.getRight();
            String firstQuery = String.format(GITHUB_API_ENDPOINT, repoName, requestedState);
            performQuery(firstQuery, releaseProject, githubImporterToken, advisories);
        }
        return advisories;
    }

    private void performQuery(String url, String releaseProject, String token, List<SecurityAdvisory> advisories)
        throws SecurityAdvisoryException
    {
        GetMethod getMethod = new GetMethod(url);
        injectHeaders(getMethod, token);
        try {
            int statusCode = this.httpClient.executeMethod(getMethod);
            if (HttpStatus.SC_OK == statusCode) {
                this.deserializer.processGithubResponse(releaseProject, getMethod.getResponseBodyAsString(),
                    advisories);
                String nextPage = getNextPage(getMethod);
                if (nextPage != null) {
                    performQuery(nextPage, releaseProject, token, advisories);
                }
            } else {
                this.logger.error("Error [{}] while trying to access [{}]", statusCode, url);
            }
        } catch (IOException e) {
            throw new SecurityAdvisoryException(String.format("Error when trying to access [%s]", url), e);
        }
    }

    private void injectHeaders(GetMethod getMethod, String token)
    {
        getMethod.addRequestHeader("Accept", HEADER_ACCEPT);
        getMethod.addRequestHeader("Authorization", String.format(GITHUB_API_TOKEN_HEADER, token));
    }

    private String getNextPage(GetMethod getMethod)
    {
        Header linkResponseHeader = getMethod.getResponseHeader(LINK_HEADER);
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
