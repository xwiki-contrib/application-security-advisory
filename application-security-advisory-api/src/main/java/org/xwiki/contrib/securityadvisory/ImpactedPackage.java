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
import java.util.Optional;

/**
 * Represent a vulnerable package information in a security advisory.
 *
 * @param ecosystem the ecosystem for this package (e.g. Maven or NPM)
 * @param packageName the identifier of the package
 * @param affectedVersionsRanges the list of ranges of affected versions
 * @param patchedVersions the list of patched versions
 * @param releasedVersions the computed list of patched versions that are released
 * @param dateOfLatestRelease the date of latest release if some patched versions are released
 *
 * @version $Id$
 * @since 2.0
 */
public record ImpactedPackage(
    String ecosystem,
    String packageName,
    List<String> affectedVersionsRanges,
    List<String> patchedVersions,
    List<String> releasedVersions,
    Optional<Date> dateOfLatestRelease
)
{
}
