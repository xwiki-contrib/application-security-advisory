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
import java.util.Optional;

import org.xwiki.component.annotation.Role;

/**
 * Component in charge of computing information related to releases.
 *
 * @version $Id$
 * @since 2.0
 */
@Role
public interface VersionReleasedManager
{
    /**
     * Compute release information of the {@link ImpactedPackage} of the advisory and returns whether or not there
     * were updates.
     * @param advisory the advisory for which to compute release information
     * @return {@code true} if updates were made and {@code false} if nothing changed
     * @throws SecurityAdvisoryException in case of problem for computing release information
     */
    boolean updateReleasedVersions(SecurityAdvisory advisory) throws SecurityAdvisoryException;

    /**
     * Get final embargo date of the advisory if all release dates of {@link ImpactedPackage} with patched versions
     * have been computed.
     *
     * @param advisory the advisory for which to get an embargo date
     * @return an embargo date or {@link Optional#empty()} if it's missing some releases.
     */
    Optional<Date> getEmbargoDate(SecurityAdvisory advisory);
}
