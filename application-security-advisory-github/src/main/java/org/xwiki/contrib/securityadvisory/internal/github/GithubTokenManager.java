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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import jakarta.inject.Inject;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;

/**
 * Simple manager to read token information.
 *
 * @version $Id$
 * @since 2.1
 */
@Component(roles = GithubTokenManager.class)
@Singleton
public class GithubTokenManager
{
    private static final String SLASH = "/";

    /**
     * Reference of the configuration document.
     */
    private static final LocalDocumentReference DOC_REFERENCE =
        new LocalDocumentReference(
            List.of("SecurityAdvisoryApplication", "Code"), "Configuration");

    @Inject
    private Provider<XWikiContext> contextProvider;

    /**
     * Read the tokens from configuration document.
     *
     * @return the map of token indexed by the orga values.
     * @throws SecurityAdvisoryException in case of problem to read the document.
     */
    public Map<String, String> getTokens() throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        Map<String, String> tokens = new HashMap<>();
        try {
            XWikiDocument document = context.getWiki().getDocument(DOC_REFERENCE, context);
            List<BaseObject> tokenObjects =
                document.getXObjects(GithubTokenClassMandatoryDocumentInitializer.CLASS_REFERENCE);
            for (BaseObject tokenObject : tokenObjects) {
                if (tokenObject != null) {
                    String orga = tokenObject.getStringValue(GithubTokenClassMandatoryDocumentInitializer.ORGA);
                    String token = tokenObject.getStringValue(GithubTokenClassMandatoryDocumentInitializer.TOKEN);
                    tokens.put(orga, token);
                }
            }
            return tokens;
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException("Error while getting tokens", e);
        }
    }

    /**
     * Retrieve the matching tokens for a given repository or orga.
     *
     * @param tokens the map of tokens as read in the configuration doc
     * @param repository the repository information (might be a repo or an orga)
     * @return the token for the given repository info
     * @throws SecurityAdvisoryException if no token can be found.
     */
    public String getTokenFromRepository(Map<String, String> tokens, String repository) throws SecurityAdvisoryException
    {
        String orga = (repository.contains(SLASH)) ? repository.substring(0, repository.indexOf(SLASH)) : repository;
        if (tokens.containsKey(orga)) {
            return tokens.get(orga);
        } else {
            throw new SecurityAdvisoryException("No token for orga " + orga);
        }
    }
}
