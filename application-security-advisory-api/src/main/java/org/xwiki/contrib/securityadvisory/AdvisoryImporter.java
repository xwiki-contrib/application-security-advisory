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

import java.util.Date;
import java.util.List;

import org.xwiki.component.annotation.Role;

/**
 * Dedicated role to allow import an advisory from an external source (e.g. from Github).
 *
 * @version $Id$
 * @since 2.0
 */
@Role
public interface AdvisoryImporter
{
    /**
     * Import all found advisories matching the given criteria.
     *
     * @param draft if {@code true} import draft advisories and ignore published ones, if {@code false} import only
     * published ones.
     * @param limitDate all advisories updated before that given date will be ignored.
     * @return a list of advisories retrieved from the external source.
     * @throws SecurityAdvisoryException in case of problem to retrieve or parse the advisories.
     */
    List<SecurityAdvisory> importAdvisories(boolean draft, Date limitDate) throws SecurityAdvisoryException;

    /**
     * Import a single advisory based on its URL.
     * @param advisoryUrl the URL of an advisory to import.
     * @param projectName the name of the project the advisory is imported to
     * @return an instance of advisory parsed from the given URL.
     * @throws SecurityAdvisoryException in case of problem to read or parse the advisory.
     */
    SecurityAdvisory importAdvisory(String advisoryUrl, String projectName) throws SecurityAdvisoryException;
}
