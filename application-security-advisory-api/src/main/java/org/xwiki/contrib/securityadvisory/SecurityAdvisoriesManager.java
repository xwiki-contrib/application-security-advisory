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
package org.xwiki.contrib.securityadvisory;

import java.util.Optional;

import org.xwiki.component.annotation.Role;
import org.xwiki.model.reference.DocumentReference;

/**
 * Represents the central manager for dealing with advisories.
 *
 * @version $Id$
 * @since 2.0
 */
@Role
public interface SecurityAdvisoriesManager
{
    /**
     * Retrieve advisories that should be now marked as disclosable and change their state before triggering an event.
     *
     * @throws SecurityAdvisoryException in case of problem for retrieving or saving the advisories
     */
    void computeDisclosable() throws SecurityAdvisoryException;

    /**
     * Retrieve advisories for which the embargo date should be computed but is not defined yet, and compute their
     * embargo date if it's possible.
     *
     * @throws SecurityAdvisoryException in case of problem to compute the embargo date
     */
    void computeEmbargoDates() throws SecurityAdvisoryException;

    /**
     * Computes the severity score of an advisory based on the contained severity vector.
     *
     * @param securityAdvisory the advisory for which to compute the score.
     * @throws SecurityAdvisoryException in case of problem to compute or write the score
     */
    void computeSeverityScore(SecurityAdvisory securityAdvisory) throws SecurityAdvisoryException;

    /**
     * Write the given advisory in an XWiki document. Note that if the document already exists it will be overridden
     * only if the flag to prevent overridding is not set.
     * @param securityAdvisory the advisory to write in a document.
     * @throws SecurityAdvisoryException in case of problem to write the document.
     */
    void writeAdvisory(SecurityAdvisory securityAdvisory) throws SecurityAdvisoryException;

    /**
     * Only write the release information of impacted packages of the given advisory. No other information is written.
     * @param securityAdvisory the advisory to write in a document.
     * @throws SecurityAdvisoryException in case of problem to write the document.
     */
    void writeAdvisoryImpactedPackagesReleaseInformation(SecurityAdvisory securityAdvisory)
        throws SecurityAdvisoryException;

    /**
     * Search for an existing advisory having the external advisory URL.
     * @param externalAdvisoryURL an advisory URL to look for in the list of existing advisories.
     * @return that advisory if it exists.
     * @throws SecurityAdvisoryException in case of problem to perform the query to look for the advisory.
     */
    Optional<SecurityAdvisory> findExistingAdvisory(String externalAdvisoryURL) throws SecurityAdvisoryException;

    /**
     * Load advisory information based on the document reference that hold it.
     * @param documentReference the document where the advisory is located.
     * @return an advisory instance or {@link Optional#empty()} if no advisory can be found.
     * @throws SecurityAdvisoryException in case of problem for loading the document.
     */
    Optional<SecurityAdvisory> loadAdvisory(DocumentReference documentReference) throws SecurityAdvisoryException;
}
