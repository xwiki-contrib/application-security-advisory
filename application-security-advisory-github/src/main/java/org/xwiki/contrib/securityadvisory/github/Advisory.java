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
package org.xwiki.contrib.securityadvisory.github;

import java.util.Date;
import java.util.List;

/**
 * An advisory as represented in Github REST API JSON schema.
 *
 * @see <a href="https://docs.github.com/en/rest/security-advisories/repository-advisories?apiVersion=2026-03-10">
 *     Github REST API doc</a>
 * @param ghsaId see linked doc.
 * @param cveId see linked doc.
 * @param htmlUrl see linked doc.
 * @param summary see linked doc.
 * @param description see linked doc.
 * @param state see linked doc.
 * @param createdAt see linked doc.
 * @param updatedAt see linked doc.
 * @param publishedAt see linked doc.
 * @param vulnerabilities see linked doc.
 * @param cvssSeverities see linked doc.
 *
 * @version $Id$
 * @since 2.0
 */
public record Advisory(
    String ghsaId,
    String cveId,
    String htmlUrl,
    String summary,
    String description,
    GithubState state,
    Date createdAt,
    Date updatedAt,
    Date publishedAt,
    List<PackageVulnerability> vulnerabilities,
    CVSSSeverities cvssSeverities
)
{
}
