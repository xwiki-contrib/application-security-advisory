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

/**
 * The state of an advisory as expressed in Github REST API JSON Schema.
 * @see <a href="https://docs.github.com/en/rest/security-advisories/repository-advisories?apiVersion=2026-03-10">
 *        Github REST API doc</a>
 * @version $Id$
 * @since 2.0
 */
public enum GithubState
{
    /**
     * See linked doc.
     */
    PUBLISHED,
    /**
     * See linked doc.
     */
    CLOSED,
    /**
     * See linked doc.
     */
    WITHDRAWN,
    /**
     * See linked doc.
     */
    DRAFT,
    /**
     * See linked doc.
     */
    TRIAGE
}
