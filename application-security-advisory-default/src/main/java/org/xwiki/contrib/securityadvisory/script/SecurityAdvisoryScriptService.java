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
import java.util.UUID;
import java.util.regex.Pattern;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.internal.VersionReleasedManager;
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
    private static final Pattern SINGLE_VERSION = Pattern.compile("^([0-9]+\\.)*[0-9]+((-milestone-|-rc-)[0-9]+)?$");

    private static final List<String> DEFAULT_ENTRIES_SPACE = Arrays.asList("SecurityAdvisoryApplication",
        "SecurityEntries");

    @Inject
    private VersionReleasedManager versionReleasedManager;

    @Inject
    private Provider<XWikiContext> contextProvider;

    /**
     * Check if the given version is released or not.
     *
     * @param product the name of the product for which to check if the version is released or not.
     * @param version the version for which to check if it's released or not.
     * @return {@code true} if the version has been released.
     * @throws SecurityAdvisoryException in case of problem to perform the query
     */
    public boolean isReleased(String product, String version) throws SecurityAdvisoryException
    {
        return this.versionReleasedManager.isVersionReleased(product, version);
    }

    /**
     * Check if the given string is a single version (e.g. 14.4.4) or a range of versions (e.g. > 14.4)
     *
     * @param version the version string to check if it's single or not
     * @return {@code true} if the version does not contain any operator and matches our version definition.
     */
    public boolean isSingleVersion(String version)
    {
        return SINGLE_VERSION.matcher(version).matches();
    }

    /**
     * Check that the new state is reachable from the current state.
     * This method basically defines the automaton of states we allow.
     *
     * @param currentStatus the current status of the advisory.
     * @param nextStatus the next requested status.
     * @return {@code true} if the transition is allowed.
     */
    public boolean isStatusUpdateAuthorized(SecurityAdvisory.State currentStatus, SecurityAdvisory.State nextStatus)
    {
        boolean result;

        // We allow any advisory to be discarded, except if it was already disclosed.
        if (nextStatus == SecurityAdvisory.State.DISCARDED) {
            result = (currentStatus != SecurityAdvisory.State.DISCLOSED);
        } else {
            // The normal cycle is:
            // Draft -> Completed -> Announced -> Disclosable -> Disclosed
            // However we allow to rollback from complete to draft, and from disclosable to announced.
            switch (currentStatus) {
                case DRAFT:
                    result = nextStatus == SecurityAdvisory.State.COMPLETED;
                    break;

                case COMPLETED:
                    result =
                        (nextStatus == SecurityAdvisory.State.DRAFT
                            || nextStatus == SecurityAdvisory.State.ANNOUNCED);
                    break;

                case ANNOUNCED:
                    result = (nextStatus == SecurityAdvisory.State.DISCLOSABLE);
                    break;

                case DISCLOSABLE:
                    result =
                        nextStatus == SecurityAdvisory.State.ANNOUNCED
                            || nextStatus == SecurityAdvisory.State.DISCLOSED;
                    break;

                default:
                    result = false;
            }
        }
        return result;
    }

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
}
